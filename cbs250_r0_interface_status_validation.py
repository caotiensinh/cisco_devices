#!/usr/bin/env python3
"""One-shot exact-target R0 live-output validation for ``show interfaces status``.

This tool is intentionally NOT a collector. It validates exactly one candidate command
under the R0 validation-only allowlist. It executes no configuration, no reboot/reload,
no interface selector, and no state-changing operation.

Raw device output remains local and is never written to sanitized evidence. If output
paginates, no pager key is sent and validation fails closed.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import getpass
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Optional

import paramiko

from cbs250_cli_discovery import CBS250ReadOnlyCrawler, DiscoveryError, clean_terminal_text
from cbs250_discovery_utils import has_more_prompt
from cbs250_safety import (
    READ_ONLY_EXEC_ALLOWLIST,
    R0_VALIDATION_EXEC_ALLOWLIST,
    assert_r0_validation_executable,
)
from cisco_assistant.documented_output_parsers import (
    DocumentedParserError,
    parse_documented_show_interfaces_status,
)
from cisco_assistant.read_only_collectors import parse_show_system, parse_show_version


TOOL_VERSION = "1.0.0"
SCHEMA_VERSION = 2
EXPECTED_PRODUCT_ID = "CBS250-24T-4X"
EXPECTED_FIRMWARE = "3.5.3.3"
VALIDATION_COMMAND = "show interfaces status"
OUTPUT_DIGEST_SCOPE = "CLEAN_TERMINAL_TEXT_UTF8"


class InterfaceStatusValidationError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_static_policy() -> None:
    command = assert_r0_validation_executable(VALIDATION_COMMAND)
    if command != VALIDATION_COMMAND:
        raise InterfaceStatusValidationError("Unexpected normalized validation command")
    if R0_VALIDATION_EXEC_ALLOWLIST != frozenset({VALIDATION_COMMAND}):
        raise InterfaceStatusValidationError("R0 validation allowlist contains unexpected commands")
    if VALIDATION_COMMAND in READ_ONLY_EXEC_ALLOWLIST:
        raise InterfaceStatusValidationError(
            "show interfaces status must not be collector-allowlisted before promotion"
        )


def build_crawler_args(args: argparse.Namespace) -> SimpleNamespace:
    return SimpleNamespace(
        host=args.host,
        username=args.username,
        port=args.port,
        timeout=args.timeout,
        quiet_time=args.quiet_time,
        help_wait=4.0,
        transport_recycle=0,
        reconnect_backoff=1.0,
        channel_open_attempts=3,
        progress_every=0,
        checkpoint_every=0,
        delay=0.0,
        include_config_help=False,
    )


def verify_exact_target(crawler: CBS250ReadOnlyCrawler) -> dict[str, str]:
    system = parse_show_system(crawler.execute_read_only("show system"))
    version = parse_show_version(crawler.execute_read_only("show version"))
    product_id = system.get("product_id")
    firmware = version.get("firmware_version")
    if product_id != EXPECTED_PRODUCT_ID or firmware != EXPECTED_FIRMWARE:
        raise InterfaceStatusValidationError(
            f"Exact target mismatch: observed={product_id!r}/{firmware!r}, "
            f"required={EXPECTED_PRODUCT_ID}/{EXPECTED_FIRMWARE}"
        )
    return {"product_id": str(product_id), "firmware_version": str(firmware)}


def execute_exact_validation_command(crawler: CBS250ReadOnlyCrawler) -> str:
    command = assert_r0_validation_executable(VALIDATION_COMMAND)
    ch: Optional[paramiko.Channel] = None
    try:
        ch, _prompt, _initial = crawler._fresh_exec_shell()
        ch.send(command + "\r")
        raw = crawler._read_quiet(ch, crawler.a.timeout)
        text = clean_terminal_text(raw)
        if has_more_prompt(text):
            raise InterfaceStatusValidationError(
                "show interfaces status output paginated; no pager key was sent"
            )
        if any(marker in text for marker in (
            "% Unrecognized command",
            "% Invalid input",
            "Command too long",
        )):
            raise DiscoveryError("Exact show interfaces status command was rejected")
        return text
    finally:
        if ch is not None:
            ch.close()


def build_sanitized_result(target: dict[str, str], text: str) -> dict[str, object]:
    try:
        rows = parse_documented_show_interfaces_status(text)
    except DocumentedParserError as exc:
        raise InterfaceStatusValidationError(
            f"Exact live show interfaces status parser validation failed: {exc}"
        ) from exc

    normalized_digest = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
    link_states = Counter(row.link_state for row in rows)
    return {
        "schema_version": SCHEMA_VERSION,
        "record_type": "R0_LIVE_OUTPUT_VALIDATION",
        "tool_version": TOOL_VERSION,
        "generated_at_utc": utc_now(),
        "status": "PASS_LIVE_PARSER_VALIDATED",
        "target": target,
        "command": VALIDATION_COMMAND,
        "risk_class": "R0",
        "normalized_output_sha256": normalized_digest,
        "output_digest_scope": OUTPUT_DIGEST_SCOPE,
        "raw_output_retained": False,
        "parser": "parse_documented_show_interfaces_status",
        "parser_result": "PASS",
        "parsed_physical_row_count": len(rows),
        "link_state_counts": dict(sorted(link_states.items())),
        "interface_ids_exported": False,
        "media_details_exported": False,
        "speed_details_exported": False,
        "port_membership_exported": False,
        "authority": {
            "device_write_authority": False,
            "production_network_write_authority": False,
            "collector_execution_authority": False,
            "validation_only_execution_authority": True,
        },
        "safety": {
            "configuration_mode_entered": False,
            "configuration_changed": False,
            "startup_config_changed": False,
            "reboot_or_reload_performed": False,
            "firmware_or_boot_state_changed": False,
            "specific_interface_command_executed": False,
            "interface_state_changed": False,
            "pager_navigation_sent": False,
        },
        "note": (
            "One-shot exact-live parser validation only. It reads aggregate interface status "
            "without selecting or changing any interface. Passing does not grant collector authority."
        ),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CBS250 exact-target interface-status R0 validation")
    parser.add_argument("--host")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--password-env", default="CBS_PASSWORD")
    parser.add_argument("--timeout", type=float, default=12.0)
    parser.add_argument("--quiet-time", type=float, default=0.6)
    parser.add_argument("--output", default="")
    parser.add_argument("--policy-check", action="store_true")
    return parser.parse_args()


def policy_check() -> int:
    validate_static_policy()
    print("[PASS] show interfaces status validation-only policy")
    print("[PASS] collector allowlist remains unchanged")
    print(f"[PASS] sanitized evidence schema v{SCHEMA_VERSION} uses {OUTPUT_DIGEST_SCOPE}")
    return 0


def main() -> int:
    args = parse_args()
    if args.policy_check:
        return policy_check()
    if not args.host:
        print("[BLOCKED] --host is required unless --policy-check is used")
        return 2

    validate_static_policy()
    password = os.getenv(args.password_env)
    if password is None:
        password = getpass.getpass(f"SSH password for {args.username}@{args.host}: ")

    crawler = CBS250ReadOnlyCrawler(build_crawler_args(args), password, Path.cwd())
    try:
        crawler.connect(reason="r0-interface-status-validation")
        target = verify_exact_target(crawler)
        text = execute_exact_validation_command(crawler)
        result = build_sanitized_result(target, text)
        rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            output = Path(args.output).expanduser().resolve()
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(rendered, encoding="utf-8")
            print(f"[PASS] Sanitized validation evidence: {output}")
        else:
            print(rendered, end="")
        return 0
    except Exception as exc:
        print(f"[BLOCKED] {type(exc).__name__}: {exc}")
        return 2
    finally:
        crawler.close()


if __name__ == "__main__":
    raise SystemExit(main())
