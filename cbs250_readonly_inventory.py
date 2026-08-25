#!/usr/bin/env python3
"""Safe CBS250 P2 read-only inventory entry point.

Current scope is intentionally small: exact identity/firmware/SSH management facts using the
three commands already present in ``cbs250_safety.READ_ONLY_EXEC_ALLOWLIST``. The output is a
sanitized partial ``CurrentNetworkState`` and never claims VLAN/port/L3 completeness.
"""
from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path
from datetime import datetime

from cisco_assistant.read_only_collectors import collect_cbs250_inventory
from cisco_assistant.read_only_transport import (
    ParamikoCBS250ReadOnlySession,
    ReadOnlySessionError,
    SessionCredentials,
)


TOOL_VERSION = "1.0.0"


def default_output_dir() -> Path:
    downloads = Path.home() / "Downloads"
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return downloads / f"CBS250_READONLY_INVENTORY_{stamp}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CBS250 exact-allowlist read-only inventory collector"
    )
    parser.add_argument("--host", required=True, help="Switch management address")
    parser.add_argument("--username", help="SSH username; prompted when omitted")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument(
        "--expected-host-key-sha256",
        help="Optional pinned SSH host-key fingerprint (SHA256:...)",
    )
    parser.add_argument("--output", type=Path, help="Output directory; defaults to Downloads")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    username = args.username or input("SSH username: ").strip()
    password = getpass.getpass(f"SSH password for {username}@{args.host}: ")
    credentials = SessionCredentials(username=username, password=password)
    out_dir = args.output or default_output_dir()
    out_dir.mkdir(parents=True, exist_ok=False)

    try:
        with ParamikoCBS250ReadOnlySession(
            args.host,
            credentials,
            port=args.port,
            timeout=args.timeout,
            expected_host_key_sha256=args.expected_host_key_sha256,
        ) as session:
            snapshot = collect_cbs250_inventory(
                session,
                source_revision=f"cbs250-readonly-inventory/{TOOL_VERSION}",
            )
    except ReadOnlySessionError as exc:
        print(f"ERROR [{exc.code.value}]: {exc}")
        return 2

    payload = snapshot.as_safe_dict()
    payload["tool"] = {
        "name": "cbs250_readonly_inventory",
        "version": TOOL_VERSION,
        "mode": "READ_ONLY",
        "exact_allowlist_only": True,
        "device_write_authority": False,
    }
    json_path = out_dir / "cbs250_readonly_inventory.json"
    json_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    lines = [
        "CBS250 READ-ONLY INVENTORY",
        "==========================",
        f"Tool version: {TOOL_VERSION}",
        "Device write authority: FALSE",
        "Raw command output exported: NO",
        "Credentials exported: NO",
        f"Planner-scope complete: {'YES' if snapshot.complete_for_planner_scope else 'NO'}",
        f"Commands succeeded: {len(snapshot.commands_succeeded)}/3",
        f"Errors: {len(snapshot.errors)}",
    ]
    if snapshot.fingerprint is not None:
        lines.extend(
            [
                f"Product: {snapshot.fingerprint.product_id}",
                f"Firmware: {snapshot.fingerprint.firmware_version}",
            ]
        )
    if snapshot.system_description:
        lines.append(f"Description: {snapshot.system_description}")
    if snapshot.ssh is not None:
        lines.append(f"SSH server enabled: {snapshot.ssh.server_enabled}")
    if snapshot.errors:
        lines.append("Issues:")
        for error in snapshot.errors:
            lines.append(f"- [{error.code}] {error.command}: {error.message}")
    lines.append(f"JSON: {json_path}")
    (out_dir / "cbs250_readonly_inventory.txt").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    print("\n".join(lines))
    return 0 if snapshot.fingerprint is not None else 3


if __name__ == "__main__":
    raise SystemExit(main())
