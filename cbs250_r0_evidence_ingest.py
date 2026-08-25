#!/usr/bin/env python3
"""Offline CBS250 R0 evidence metadata ingester.

This CLI DOES NOT connect to a switch and DOES NOT execute commands. It reads an already
captured UTF-8 text file, validates the command against the reviewed R0 candidate registry,
and writes digest-only metadata. Raw command output is never copied into the metadata file.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from cisco_assistant.r0_evidence import R0EvidenceError, ingest_external_r0_output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Offline CBS250 R0 evidence metadata ingestion")
    parser.add_argument("--command", required=True, help="Exact reviewed R0 candidate command")
    parser.add_argument("--input-file", required=True, help="Existing raw capture text file")
    parser.add_argument("--product-id", default="CBS250-24T-4X")
    parser.add_argument("--firmware", default="3.5.3.3")
    parser.add_argument("--source-label", required=True, help="Non-secret provenance label")
    parser.add_argument("--metadata-output", default="", help="Optional metadata JSON output path")
    return parser.parse_args()


def build_metadata(args: argparse.Namespace) -> dict[str, object]:
    input_path = Path(args.input_file).expanduser().resolve()
    if not input_path.is_file():
        raise R0EvidenceError(f"Input evidence file does not exist: {input_path}")

    try:
        raw_output = input_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise R0EvidenceError(f"Cannot read UTF-8 evidence file {input_path}: {exc}") from exc

    record = ingest_external_r0_output(
        command=args.command,
        product_id=args.product_id,
        firmware_version=args.firmware,
        raw_output=raw_output,
        source_label=args.source_label,
    )
    payload = record.as_dict()
    payload["schema_version"] = 1
    payload["input_filename"] = input_path.name
    payload["note"] = (
        "Digest-only offline ingestion. The capture is not independently proven live by this "
        "tool and grants no execution or write authority."
    )
    return payload


def main() -> int:
    args = parse_args()
    try:
        payload = build_metadata(args)
        rendered = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
        if args.metadata_output:
            output_path = Path(args.metadata_output).expanduser().resolve()
            input_path = Path(args.input_file).expanduser().resolve()
            if output_path == input_path:
                raise R0EvidenceError("metadata output must not overwrite the raw evidence file")
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(rendered, encoding="utf-8")
            print(f"[PASS] Metadata written: {output_path}")
        else:
            sys.stdout.write(rendered)
        return 0
    except R0EvidenceError as exc:
        print(f"[BLOCKED] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
