# CBS250 Live Evidence

This directory stores normalized, model/firmware-bound knowledge derived from live Cisco CBS250 discovery runs.

## Evidence rules

- Live evidence is scoped to the exact observed model, firmware, privilege level and CLI mode.
- A discovered command is evidence of syntax exposure, not permission to execute it.
- Safety evidence and discovery completeness are stored with every dataset.
- Transport/parser failures do not prove a command is unsupported.
- Partial or limit-truncated datasets must remain explicitly marked as such even if the original tool process finished normally.
- Public repository records omit deployment identifiers such as management IPs, usernames, device MAC addresses, SSH fingerprints and active-session source addresses.
- Raw transcripts are not required in the public repository. Their SHA-256 digests may be retained in normalized records for provenance verification.

## Current datasets

- `CBS250-24T-4X_3.5.3.3_20260825_v31.json` — current exact live reference. Active firmware 3.5.3.3; 12,006 discovered nodes, 4,698 help queries, zero runtime errors, privileged EXEC root 39/39. The original v3.1.0 summary said `COMPLETE`, but the normalized record correctly marks grammar coverage `TRUNCATED_AT_MAX_NODES` because the run reached the 12,000-node full-safe ceiling.
- `CBS250-24T-4X_3.3.0.16_20260825_v3.json` — historical v3 investigation-only evidence; 774 nodes, 679 help queries, safety PASS, completeness PARTIAL because root `?` output paged after the 22nd command.

New read-only command grammar discovered on 3.5.3.3 is reviewed separately in `knowledge/cbs250/r0_candidate_review_3.5.3.3.json`. Candidate review does not grant execution authority.

The earlier human-readable v3 analysis is in `docs/CBS250/live_discovery_20260825.md`.
