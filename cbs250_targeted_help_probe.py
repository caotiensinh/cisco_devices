#!/usr/bin/env python3
"""Exact-bound targeted CBS250 context-help probe.

This tool exists to close narrow live grammar gaps without rerunning the full crawler.
It executes only the already-approved inventory commands ``show system`` and ``show version``
to bind the session to the exact target. Candidate prefixes are NEVER submitted with Enter;
they are typed only as context-help queries ending in ``?`` on disposable SSH channels.

After the literal ``?`` is sent, the underlying v3.1 transport sends zero further bytes on
that channel and destroys the channel after reading help output.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
from types import SimpleNamespace
from datetime import datetime, timezone

from cbs250_cli_discovery import CBS250ReadOnlyCrawler
from cbs250_safety import READ_ONLY_EXEC_ALLOWLIST
from cisco_assistant.read_only_collectors import parse_show_system, parse_show_version


TOOL_VERSION = "1.0.0"
EXPECTED_PRODUCT_ID = "CBS250-24T-4X"
EXPECTED_FIRMWARE = "3.5.3.3"
APPROVED_BINDING_COMMANDS = frozenset({"show system", "show version"})
L3_HELP_PREFIXES = (
    "show ip interface",
    "show ip route",
    "show ip route summary",
)


class TargetedProbeError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_static_policy() -> None:
    if not APPROVED_BINDING_COMMANDS.issubset(READ_ONLY_EXEC_ALLOWLIST):
        raise TargetedProbeError("Binding command set exceeds exact read-only execution allowlist")
    if any(command not in {"show system", "show version"} for command in APPROVED_BINDING_COMMANDS):
        raise TargetedProbeError("Unexpected targeted-probe binding command")
    for prefix in L3_HELP_PREFIXES:
        validate_probe_prefix(prefix)


def validate_probe_prefix(prefix: str) -> str:
    normalized = " ".join(prefix.strip().split())
    if not normalized:
        raise TargetedProbeError("Empty help prefix is forbidden")
    if "\r" in prefix or "\n" in prefix or "?" in prefix:
        raise TargetedProbeError("Help prefix must not contain CR/LF or a question-mark marker")
    if normalized not in L3_HELP_PREFIXES:
        raise TargetedProbeError(f"Prefix is outside the exact targeted-help allowlist: {normalized!r}")
    return normalized


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
    system_text = crawler.execute_read_only("show system")
    version_text = crawler.execute_read_only("show version")
    system = parse_show_system(system_text)
    version = parse_show_version(version_text)

    product_id = system.get("product_id")
    firmware = version.get("firmware_version")
    if product_id != EXPECTED_PRODUCT_ID or firmware != EXPECTED_FIRMWARE:
        raise TargetedProbeError(
            "Exact target binding failed: "
            f"observed={product_id!r}/{firmware!r}, "
            f"required={EXPECTED_PRODUCT_ID}/{EXPECTED_FIRMWARE}"
        )
    return {"product_id": str(product_id), "firmware_version": str(firmware)}


def probe_prefix(crawler: CBS250ReadOnlyCrawler, prefix: str) -> dict[str, object]:
    normalized = validate_probe_prefix(prefix)
    before = len(crawler.audit)
    items, paginated = crawler.query_help_once("privileged_exec", normalized)
    audit = crawler.audit[-1] if len(crawler.audit) > before else None

    return {
        "prefix": normalized,
        "query": f"{normalized} ?",
        "candidate_command_executed": False,
        "help_query_submitted_with_enter": False,
        "bytes_sent_after_help_marker": None if audit is None else audit.bytes_sent_after_help_marker,
        "channel_closed_immediately": None if audit is None else audit.channel_closed_immediately,
        "paginated": paginated,
        "terminal_cr_observed": any(item.token == "<CR>" for item in items),
        "items": [
            {
                "token": item.token,
                "description": item.description,
                "kind": item.kind,
                "risk": item.risk,
            }
            for item in items
        ],
        "error": None if audit is None else audit.error,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Exact-bound CBS250 3.5.3.3 L3 context-help probe; candidate commands are never executed"
    )
    parser.add_argument("--host", required=True)
    parser.add_argument("--username", default="admin")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--password-env", default="CBS_PASSWORD")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--help-wait", type=float, default=4.0)
    parser.add_argument("--quiet-time", type=float, default=0.45)
    parser.add_argument("--delay", type=float, default=0.05)
    parser.add_argument("--reconnect-backoff", type=float, default=1.0)
    parser.add_argument("--channel-open-attempts", type=int, default=3)
    parser.add_argument("--output-dir", default="")
    parser.add_argument("--policy-check", action="store_true")
    return parser.parse_args()


def policy_check() -> int:
    validate_static_policy()
    assert APPROVED_BINDING_COMMANDS == frozenset({"show system", "show version"})
    assert all(command in READ_ONLY_EXEC_ALLOWLIST for command in APPROVED_BINDING_COMMANDS)
    assert all(prefix not in READ_ONLY_EXEC_ALLOWLIST for prefix in L3_HELP_PREFIXES)
    print("[PASS] targeted L3 help probe policy")
    print("[PASS] candidate prefixes are help-only and outside executable allowlist")
    return 0


def main() -> int:
    args = parse_args()
    if args.policy_check:
        return policy_check()

    validate_static_policy()
    password = os.getenv(args.password_env)
    if password is None:
        password = getpass.getpass(f"SSH password for {args.username}@{args.host}: ")

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = (
        Path(args.output_dir).expanduser().resolve()
        if args.output_dir
        else Path.home() / "Downloads" / f"CBS250_Targeted_L3_Help_{stamp}"
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    crawler = CBS250ReadOnlyCrawler(build_crawler_args(args), password, out_dir)
    results: list[dict[str, object]] = []
    try:
        crawler.connect(reason="targeted-help-probe")
        target = verify_exact_target(crawler)
        for prefix in L3_HELP_PREFIXES:
            results.append(probe_prefix(crawler, prefix))
    except Exception as exc:
        summary = {
            "schema_version": 1,
            "tool_version": TOOL_VERSION,
            "generated_at_utc": utc_now(),
            "status": "BLOCKED",
            "error": f"{type(exc).__name__}: {exc}",
            "authority": {
                "device_write_authority": False,
                "candidate_execution_authority": False,
            },
            "results": results,
        }
        (out_dir / "targeted_l3_help_summary.json").write_text(
            json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        (out_dir / "targeted_l3_help_transcript.txt").write_text(
            crawler.transcript.text(), encoding="utf-8"
        )
        print(f"[BLOCKED] {exc}")
        print(f"[+] Output: {out_dir}")
        return 2
    finally:
        crawler.close()

    safe = all(
        result["bytes_sent_after_help_marker"] == 0
        and result["channel_closed_immediately"] is True
        and result["error"] is None
        for result in results
    )
    summary = {
        "schema_version": 1,
        "tool_version": TOOL_VERSION,
        "generated_at_utc": utc_now(),
        "status": "PASS" if safe else "BLOCKED",
        "target": target,
        "authority": {
            "device_write_authority": False,
            "production_network_write_authority": False,
            "candidate_execution_authority": False,
            "binding_execution_commands": sorted(APPROVED_BINDING_COMMANDS),
            "candidate_help_prefixes": list(L3_HELP_PREFIXES),
        },
        "safety": {
            "candidate_commands_executed": False,
            "help_query_submitted_with_enter": False,
            "disposable_channel_per_help_query": True,
            "required_bytes_sent_after_help_marker": 0,
            "config_mode_entered": False,
        },
        "results": results,
    }
    (out_dir / "targeted_l3_help_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (out_dir / "targeted_l3_help_transcript.txt").write_text(
        crawler.transcript.text(), encoding="utf-8"
    )

    print(f"[{'PASS' if safe else 'BLOCKED'}] Exact-target L3 context-help probe")
    print(f"[+] Target: {target['product_id']} / {target['firmware_version']}")
    print(f"[+] Output: {out_dir}")
    return 0 if safe else 2


if __name__ == "__main__":
    raise SystemExit(main())
