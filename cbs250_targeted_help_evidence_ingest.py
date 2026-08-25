#!/usr/bin/env python3
"""Offline CLI for sanitized CBS250 targeted-help evidence ingestion.

This tool performs no network or device access. It validates a completed targeted-help summary
and writes a sanitized grammar-evidence JSON record that grants no execution or write authority.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from cisco_assistant.targeted_help_evidence import (
    TargetedHelpEvidenceError,
    ingest_targeted_help_summary,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Offline CBS250 targeted-help summary validation and sanitization"
    )
    parser.add_argument("--input-summary", required=True)
    parser.add_argument("--output", default="")
    return parser.parse_args()


def build_sanitized_payload(input_summary: str) -> dict[str, object]:
    record = ingest_targeted_help_summary(Path(input_summary).expanduser().resolve())
    return record.as_dict()


def main() -> int:
    args = parse_args()
    try:
        input_path = Path(args.input_summary).expanduser().resolve()
        payload = build_sanitized_payload(str(input_path))
        rendered = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"

        if args.output:
            output_path = Path(args.output).expanduser().resolve()
            if output_path == input_path:
                raise TargetedHelpEvidenceError(
                    "sanitized evidence output must not overwrite the original probe summary"
                )
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(rendered, encoding="utf-8")
            print(f"[PASS] Sanitized evidence written: {output_path}")
        else:
            sys.stdout.write(rendered)
        return 0
    except TargetedHelpEvidenceError as exc:
        print(f"[BLOCKED] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
