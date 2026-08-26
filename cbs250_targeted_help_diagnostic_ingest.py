#!/usr/bin/env python3
"""Offline CLI for sanitized CBS250 targeted-help diagnostics."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from cisco_assistant.targeted_help_diagnostic import (
    TargetedHelpDiagnosticError,
    ingest_targeted_help_diagnostic,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Offline CBS250 safe targeted-help diagnostic sanitization"
    )
    parser.add_argument("--input-summary", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        input_path = Path(args.input_summary).expanduser().resolve()
        output_path = Path(args.output).expanduser().resolve()
        if output_path == input_path:
            raise TargetedHelpDiagnosticError("diagnostic output must not overwrite source summary")
        record = ingest_targeted_help_diagnostic(input_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(record.as_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(f"[PASS] Sanitized diagnostic written: {output_path}")
        return 0
    except TargetedHelpDiagnosticError as exc:
        print(f"[BLOCKED] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
