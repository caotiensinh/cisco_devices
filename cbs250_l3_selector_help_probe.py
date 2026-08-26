#!/usr/bin/env python3
"""Exact-target CBS250 L3 selector-level context-help probe.

The probe executes only already-approved exact-target binding commands (show system,
show version). Every L3 selector is queried only as context help ending in '?' without
Enter, on a disposable SSH channel with zero bytes sent after the help marker.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import getpass
import json
import os
from pathlib import Path
from types import SimpleNamespace

from cbs250_cli_discovery import CBS250ReadOnlyCrawler
from cbs250_safety import READ_ONLY_EXEC_ALLOWLIST
from cisco_assistant.read_only_collectors import parse_show_system, parse_show_version


TOOL_VERSION = "1.0.0"
EXPECTED_PRODUCT_ID = "CBS250-24T-4X"
EXPECTED_FIRMWARE = "3.5.3.3"
APPROVED_BINDING_COMMANDS = frozenset({"show system", "show version"})
SELECTOR_HELP_PREFIXES = (
    "show ip interface GigabitEthernet",
    "show ip interface TenGigabitEthernet",
    "show ip interface Port-Channel",
    "show ip interface Loopback",
    "show ip interface Tunnel",
    "show ip interface Vlan",
    "show ip route address",
    "show ip route connected",
    "show ip route static",
    "show ip route rejected",
    "show ip route summary",
)


class SelectorProbeError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_prefix(prefix: str) -> str:
    normalized = " ".join(prefix.strip().split())
    if not normalized or normalized not in SELECTOR_HELP_PREFIXES:
        raise SelectorProbeError(f"Prefix is outside exact selector-help allowlist: {normalized!r}")
    if any(ch in prefix for ch in ("\r", "\n", "?")):
        raise SelectorProbeError("Selector-help prefix must not contain CR/LF or '?'")
    return normalized


def validate_static_policy() -> None:
    if APPROVED_BINDING_COMMANDS != frozenset({"show system", "show version"}):
        raise SelectorProbeError("Unexpected binding command set")
    if not APPROVED_BINDING_COMMANDS.issubset(READ_ONLY_EXEC_ALLOWLIST):
        raise SelectorProbeError("Binding command exceeds read-only allowlist")
    for prefix in SELECTOR_HELP_PREFIXES:
        validate_prefix(prefix)
        if prefix in READ_ONLY_EXEC_ALLOWLIST:
            raise SelectorProbeError("Selector-help prefix must remain outside execution allowlist")


def build_crawler_args(args: argparse.Namespace) -> SimpleNamespace:
    return SimpleNamespace(
        host=args.host,
        username=args.username,
        port=args.port,
        timeout=args.timeout,
        quiet_time=args.quiet_time,
        help_wait=args.help_wait,
        transport_recycle=0,
        reconnect_backoff=args.reconnect_backoff,
        channel_open_attempts=args.channel_open_attempts,
        progress_every=0,
        checkpoint_every=0,
        delay=args.delay,
        include_config_help=False,
    )


def verify_exact_target(crawler: CBS250ReadOnlyCrawler) -> dict[str, str]:
    system = parse_show_system(crawler.execute_read_only("show system"))
    version = parse_show_version(crawler.execute_read_only("show version"))
    product_id = system.get("product_id")
    firmware = version.get("firmware_version")
    if product_id != EXPECTED_PRODUCT_ID or firmware != EXPECTED_FIRMWARE:
        raise SelectorProbeError(
            f"Exact target mismatch: observed={product_id!r}/{firmware!r}, "
            f"required={EXPECTED_PRODUCT_ID}/{EXPECTED_FIRMWARE}"
        )
    return {"product_id": str(product_id), "firmware_version": str(firmware)}


def probe_prefix(crawler: CBS250ReadOnlyCrawler, prefix: str) -> dict[str, object]:
    normalized = validate_prefix(prefix)
    before = len(crawler.audit)
    items, paginated = crawler.query_help_once("privileged_exec", normalized)
    audit = crawler.audit[-1] if len(crawler.audit) > before else None
    return {
        "prefix": normalized,
        "candidate_command_executed": False,
        "help_query_submitted_with_enter": False,
        "bytes_sent_after_help_marker": None if audit is None else audit.bytes_sent_after_help_marker,
        "channel_closed_immediately": None if audit is None else audit.channel_closed_immediately,
        "paginated": paginated,
        "terminal_cr_observed": any(item.token == "<CR>" for item in items),
        "observed_tokens": [item.token for item in items],
        "error": None if audit is None else audit.error,
    }


def classify(results: list[dict[str, object]]) -> dict[str, object]:
    safety_pass = len(results) == len(SELECTOR_HELP_PREFIXES) and all(
        result.get("candidate_command_executed") is False
        and result.get("help_query_submitted_with_enter") is False
        and result.get("bytes_sent_after_help_marker") == 0
        and result.get("channel_closed_immediately") is True
        and result.get("error") is None
        for result in results
    )
    return {
        "status": "PASS_SAFE_HELP" if safety_pass else "BLOCKED_SAFETY",
        "safety_status": "PASS" if safety_pass else "BLOCKED",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Exact CBS250 3.5.3.3 selector-level L3 context-help probe")
    parser.add_argument("--host")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--password-env", default="CBS_PASSWORD")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--help-wait", type=float, default=4.0)
    parser.add_argument("--quiet-time", type=float, default=0.45)
    parser.add_argument("--delay", type=float, default=0.05)
    parser.add_argument("--reconnect-backoff", type=float, default=1.0)
    parser.add_argument("--channel-open-attempts", type=int, default=3)
    parser.add_argument("--output", default="")
    parser.add_argument("--policy-check", action="store_true")
    return parser.parse_args()


def policy_check() -> int:
    validate_static_policy()
    print("[PASS] selector-level L3 help policy")
    print("[PASS] all selector prefixes remain help-only and outside executable allowlist")
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

    output = Path(args.output).expanduser().resolve() if args.output else Path.cwd() / "selector_l3_help_summary.json"
    crawler = CBS250ReadOnlyCrawler(build_crawler_args(args), password, output.parent)
    results: list[dict[str, object]] = []
    try:
        crawler.connect(reason="selector-level-l3-help")
        target = verify_exact_target(crawler)
        for prefix in SELECTOR_HELP_PREFIXES:
            results.append(probe_prefix(crawler, prefix))
        classification = classify(results)
        summary = {
            "schema_version": 1,
            "tool_version": TOOL_VERSION,
            "generated_at_utc": utc_now(),
            **classification,
            "target": target,
            "authority": {
                "device_write_authority": False,
                "production_network_write_authority": False,
                "candidate_execution_authority": False,
            },
            "safety": {
                "candidate_commands_executed": False,
                "help_query_submitted_with_enter": False,
                "disposable_channel_per_help_query": True,
                "required_bytes_sent_after_help_marker": 0,
                "config_mode_entered": False,
                "specific_interface_identifier_queried": False,
            },
            "results": results,
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"[{classification['status']}] Selector-level L3 context-help probe")
        print(f"[+] Target: {target['product_id']} / {target['firmware_version']}")
        print(f"[+] Output: {output}")
        return 0 if classification["safety_status"] == "PASS" else 2
    except Exception as exc:
        print(f"[BLOCKED] {type(exc).__name__}: {exc}")
        return 2
    finally:
        crawler.close()


if __name__ == "__main__":
    raise SystemExit(main())
