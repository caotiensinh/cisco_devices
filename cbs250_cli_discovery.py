#!/usr/bin/env python3
"""
CBS250 CLI Capability Discovery v3.1 -- INVESTIGATION ONLY.

Primary safety invariant:
    one context-help query == one disposable SSH shell channel

After the literal '?' is sent, v3.1 sends ZERO more bytes on that channel. It
never sends Enter, Ctrl-C, pager navigation, a sync sequence, or another command.
The channel is read until quiet and then destroyed.

v3.1 adds safe auto-sharding for paginated help. If Cisco returns a More prompt,
the crawler does NOT press Space. Instead it opens fresh channels and asks
partial-keyword help such as 's?' or 'show s?'. This keeps the zero-byte-after-?
invariant while recovering command options hidden behind pagination.

Discovered command text is data only and is never executed.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import re
import socket
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

try:
    import paramiko
except ImportError:
    print('ERROR: install dependency: python -m pip install "paramiko>=3.4,<5"', file=sys.stderr)
    raise SystemExit(2)

from cbs250_discovery_utils import (
    SHARD_ALPHABET,
    build_help_query,
    has_more_prompt,
    merge_unique_items,
)
from cbs250_safety import (
    VERSION,
    HARD_DENY_EXEC_ROOTS,
    READ_ONLY_EXEC_ALLOWLIST,
    SafetyViolation,
    assert_read_only_executable,
    normalize_command,
)

ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
HELP_LINE_RE = re.compile(r"^\s+(\S+)(?:\s{2,}|\t+)(.*\S)?\s*$")

ROOT_RISK = {
    "show": "read_only", "dir": "read_only", "pwd": "read_only",
    "more": "read_only", "help": "read_only", "ping": "diagnostic_network",
    "traceroute": "diagnostic_network", "terminal": "session_only",
    "cd": "session_only", "exit": "session_control", "disable": "session_control",
    "login": "session_control", "resume": "session_control",
    "ssh": "outbound_session", "telnet": "outbound_session",
    "configure": "mode_entry_only", "boot": "dangerous", "clear": "dangerous",
    "copy": "state_changing", "delete": "destructive", "reload": "destructive",
    "write": "state_changing", "set": "state_changing", "no": "state_changing",
    "crypto": "state_changing", "debug-mode": "state_changing",
    "system": "state_changing", "test": "diagnostic_may_affect_state",
    "dot1x": "state_changing", "errdisable": "state_changing",
    "green-ethernet": "state_changing", "macro": "state_changing",
    "mkdir": "state_changing", "rename": "state_changing",
    "renew": "state_changing", "rmdir": "destructive",
}

KNOWN_PLACEHOLDERS = frozenset({
    "WORD", "STRING", "LINE", "NAME", "HOSTNAME", "USERNAME", "PASSWORD",
    "FILENAME", "URL", "IP", "IPV4", "IPV6", "ADDRESS", "MAC", "VLAN-ID",
    "VLANID", "PORT", "PORT-ID", "INTERFACE", "INTEGER", "NUMBER", "SECONDS",
})

NON_RECURSIVE_WRAPPERS = frozenset({"do"})


class DiscoveryError(RuntimeError):
    pass


@dataclass
class HelpItem:
    token: str
    description: str
    kind: str
    risk: str


@dataclass
class QueryAudit:
    mode: str
    context_prefix: str
    shard: str
    query: str
    prompt: str
    paginated: bool
    bytes_sent_after_help_marker: int
    channel_closed_immediately: bool
    error: Optional[str] = None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def clean_terminal_text(text: str) -> str:
    text = ANSI_RE.sub("", text).replace("\x00", "")
    out: list[str] = []
    for ch in text:
        if ch == "\b":
            if out and out[-1] not in "\r\n":
                out.pop()
        else:
            out.append(ch)
    return "".join(out).replace("\r\n", "\n").replace("\r", "\n")


def is_placeholder(token: str) -> bool:
    token = token.strip()
    if not token or token == "<CR>":
        return False
    if token.startswith(("<", "[", "{")):
        return True
    if re.search(r"<[^>]+>$", token):
        return True
    if token.upper() in KNOWN_PLACEHOLDERS:
        return True
    if re.fullmatch(r"[A-Z](?:\.[A-Z]){3}", token):
        return True
    return False


def is_keyword(token: str) -> bool:
    if not token or token == "<CR>" or is_placeholder(token):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9*_.:/-]+", token))


def ssh_fingerprint(key: "paramiko.PKey") -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


class Transcript:
    def __init__(self) -> None:
        self.parts: list[str] = []

    def add(self, label: str, raw: str) -> None:
        self.parts.append(
            f"\n===== {utc_now()} | {label} =====\n{clean_terminal_text(raw)}\n"
        )

    def text(self) -> str:
        return "".join(self.parts)


class CBS250ReadOnlyCrawler:
    def __init__(self, args: argparse.Namespace, password: str, out_dir: Path) -> None:
        self.a = args
        self.password = password
        self.out_dir = out_dir
        self.transport: Optional[paramiko.Transport] = None
        self.transcript = Transcript()
        self.nodes = 0
        self.help_queries = 0
        self.errors: list[dict[str, Any]] = []
        self.audit: list[QueryAudit] = []
        self.visited: set[tuple[str, str, str]] = set()
        self.host_key = {"type": "", "bits": 0, "fingerprint": ""}
        self.started = time.monotonic()
        self.current_mode = ""
        self.current_query = ""
        self.mode_trees: dict[str, dict[str, Any]] = {}
        self.inventory: dict[str, str] = {}
        self.pager_events = 0
        self.shard_queries = 0
        self.transport_recycles = 0
        self._last_recycle_at = 0

    def connect(self, *, reason: str = "initial") -> None:
        self.close()
        sock = socket.create_connection(
            (self.a.host, self.a.port), timeout=self.a.timeout
        )
        t = paramiko.Transport(sock)
        try:
            try:
                sec = t.get_security_options()
                keys = [k for k in sec.key_types if k != "ssh-dss"]
                if "ssh-rsa" not in keys:
                    keys.append("ssh-rsa")
                sec.key_types = tuple(keys)
            except Exception:
                pass
            t.start_client(timeout=self.a.timeout)
            key = t.get_remote_server_key()
            self.host_key = {
                "type": key.get_name(),
                "bits": key.get_bits(),
                "fingerprint": ssh_fingerprint(key),
            }
            self.transcript.add(
                f"SSH NEGOTIATION ({reason})",
                json.dumps(self.host_key, indent=2),
            )
            password_error: Optional[Exception] = None
            try:
                t.auth_password(self.a.username, self.password, fallback=False)
            except paramiko.AuthenticationException as exc:
                password_error = exc
            if not t.is_authenticated():
                prompts: list[str] = []
                def handler(_title: str, _instructions: str, questions: Iterable):
                    qs = list(questions)
                    answers: list[str] = []
                    for prompt, _echo in qs:
                        prompt = str(prompt)
                        prompts.append(prompt[:160])
                        if "password" in prompt.lower() or len(qs) == 1:
                            answers.append(self.password)
                        else:
                            answers.append("")
                    return answers
                try:
                    t.auth_interactive(self.a.username, handler)
                except paramiko.AuthenticationException as exc:
                    raise DiscoveryError(
                        "Authentication failed for password and keyboard-interactive; "
                        f"prompts={prompts!r}; password_error={password_error}; "
                        f"interactive_error={exc}"
                    ) from exc
            if not t.is_authenticated():
                raise DiscoveryError("SSH authentication not established")
            self.transport = t
        except Exception:
            t.close()
            raise

    def close(self) -> None:
        if self.transport is not None:
            try:
                self.transport.close()
            finally:
                self.transport = None

    def _maybe_recycle_transport(self) -> None:
        interval = max(0, self.a.transport_recycle)
        if interval <= 0 or self.help_queries == 0:
            return
        if self.help_queries % interval == 0 and self.help_queries != self._last_recycle_at:
            self._last_recycle_at = self.help_queries
            self.transport_recycles += 1
            print(f"[+] Recycling SSH transport safely after {self.help_queries} help queries")
            self.connect(reason=f"recycle-{self.transport_recycles}")
            time.sleep(max(0.0, self.a.reconnect_backoff))

    def _new_shell(self) -> "paramiko.Channel":
        self._maybe_recycle_transport()
        last_error: Optional[Exception] = None
        attempts = max(1, self.a.channel_open_attempts)
        for attempt in range(1, attempts + 1):
            try:
                if self.transport is None or not self.transport.is_authenticated():
                    self.connect(reason="channel-recovery")
                assert self.transport is not None
                ch = self.transport.open_session(timeout=self.a.timeout)
                ch.get_pty(term="vt100", width=240, height=2000)
                ch.invoke_shell()
                ch.settimeout(0.25)
                return ch
            except Exception as exc:
                last_error = exc
                if attempt >= attempts:
                    break
                self.transport_recycles += 1
                self.connect(reason=f"channel-open-retry-{attempt}")
                time.sleep(self.a.reconnect_backoff * attempt)
        raise DiscoveryError(
            f"Unable to open disposable SSH channel after {attempts} attempts: {last_error}"
        )

    def _read_quiet(self, ch: "paramiko.Channel", max_wait: float, quiet: Optional[float] = None) -> str:
        quiet = self.a.quiet_time if quiet is None else quiet
        chunks: list[str] = []
        start = last = time.monotonic()
        while time.monotonic() - start < max_wait:
            got = False
            try:
                while ch.recv_ready():
                    data = ch.recv(65535)
                    if not data:
                        break
                    chunks.append(data.decode("utf-8", errors="replace"))
                    last = time.monotonic()
                    got = True
            except socket.timeout:
                pass
            if chunks and time.monotonic() - last >= quiet:
                break
            if not got:
                time.sleep(0.03)
        return "".join(chunks)

    @staticmethod
    def _prompt(raw: str) -> str:
        lines = [x.strip() for x in clean_terminal_text(raw).splitlines() if x.strip()]
        candidates = [x for x in lines if x.endswith(("#", ">")) and len(x) <= 160]
        return candidates[-1] if candidates else ""

    def _fresh_exec_shell(self) -> tuple["paramiko.Channel", str, str]:
        ch = self._new_shell()
        raw = self._read_quiet(ch, self.a.timeout)
        prompt = self._prompt(raw)
        if not prompt:
            ch.send("\r")
            raw2 = self._read_quiet(ch, 3.0)
            raw += raw2
            prompt = self._prompt(raw)
        if not prompt or "(config" in prompt:
            ch.close()
            raise DiscoveryError(f"Clean EXEC prompt not established: {prompt!r}")
        return ch, prompt, raw

    def execute_read_only(self, command: str) -> str:
        command = assert_read_only_executable(command)
        ch: Optional[paramiko.Channel] = None
        try:
            ch, _prompt, initial = self._fresh_exec_shell()
            self.transcript.add(f"READONLY INITIAL {command}", initial)
            ch.send(command + "\r")
            raw = self._read_quiet(ch, self.a.timeout)
            self.transcript.add(f"READONLY EXEC {command}", raw)
            text = clean_terminal_text(raw)
            if any(x in text for x in ("% Unrecognized command", "% Invalid input", "Command too long")):
                raise DiscoveryError(f"Read-only inventory command rejected: {command!r}")
            return text
        finally:
            if ch is not None:
                ch.close()

    def _enter_ephemeral_config(self, ch: "paramiko.Channel", prompt: str) -> tuple[str, str]:
        if not self.a.include_config_help:
            raise SafetyViolation("Config help disabled")
        ch.send("configure terminal\r")
        raw = self._read_quiet(ch, 3.0)
        new_prompt = self._prompt(raw)
        if "(config" not in new_prompt:
            ch.send("configure\r")
            raw2 = self._read_quiet(ch, 3.0)
            raw += raw2
            new_prompt = self._prompt(raw)
        if "(config" not in new_prompt:
            raise DiscoveryError(f"Ephemeral config prompt not established: {new_prompt!r}")
        return new_prompt, raw

    def _progress(self) -> None:
        if self.a.progress_every <= 0 or self.help_queries % self.a.progress_every != 0:
            return
        elapsed = int(time.monotonic() - self.started)
        hh, rem = divmod(elapsed, 3600)
        mm, ss = divmod(rem, 60)
        print(
            f"[PROGRESS] elapsed={hh:02d}:{mm:02d}:{ss:02d} queries={self.help_queries} "
            f"nodes={self.nodes} errors={len(self.errors)} pager={self.pager_events} "
            f"mode={self.current_mode} query={self.current_query!r}"
        )

    def _checkpoint(self) -> None:
        if self.a.checkpoint_every <= 0 or self.help_queries % self.a.checkpoint_every != 0:
            return
        payload = {
            "tool_version": VERSION,
            "generated_at_utc": utc_now(),
            "status": "IN_PROGRESS",
            "safety": {
                "mode": "INVESTIGATION_ONLY",
                "zero_bytes_after_help_marker": True,
                "disposable_channel_per_help_query": True,
                "discovered_commands_executed": False,
            },
            "progress": {
                "nodes_found": self.nodes,
                "help_queries": self.help_queries,
                "errors": len(self.errors),
                "pager_events": self.pager_events,
                "shard_queries": self.shard_queries,
                "transport_recycles": self.transport_recycles,
                "current_mode": self.current_mode,
                "current_query": self.current_query,
            },
            "completed_top_level": {
                mode: [k for k in tree if k != "_meta"]
                for mode, tree in self.mode_trees.items()
            },
        }
        (self.out_dir / "cbs250_checkpoint_v31.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        (self.out_dir / "cbs250_raw_transcript_v31.partial.txt").write_text(
            self.transcript.text(), encoding="utf-8"
        )

    def _parse_help(self, text: str, context_prefix: str, query: str) -> list[HelpItem]:
        result: list[HelpItem] = []
        seen: set[str] = set()
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped == query or stripped.endswith(query):
                continue
            if has_more_prompt(stripped) or stripped.startswith("More:"):
                continue
            m = HELP_LINE_RE.match(line)
            if not m:
                continue
            token = m.group(1).strip()
            if token in seen:
                continue
            seen.add(token)
            desc = (m.group(2) or "").strip()
            if token == "<CR>":
                kind = "terminal"
            elif is_placeholder(token):
                kind = "placeholder"
            elif is_keyword(token):
                kind = "keyword"
            else:
                kind = "unknown"
            root = (context_prefix.split()[0] if context_prefix else token).lower()
            result.append(HelpItem(token, desc, kind, ROOT_RISK.get(root, "unknown")))
        return result

    def query_help_once(self, mode: str, context_prefix: str, shard: str = "") -> tuple[list[HelpItem], bool]:
        context_prefix = normalize_command(context_prefix)
        shard = shard.strip()
        key = (mode, context_prefix, shard)
        if key in self.visited:
            return [], False
        self.visited.add(key)
        query = build_help_query(context_prefix, shard)
        if "\r" in query or "\n" in query:
            raise SafetyViolation("Help query contains a line terminator")
        self.current_mode = mode
        self.current_query = query
        ch: Optional[paramiko.Channel] = None
        prompt = ""
        raw_help = ""
        closed_immediately = False
        paginated = False
        try:
            ch, prompt, initial = self._fresh_exec_shell()
            self.transcript.add(f"HELP INITIAL [{mode}] {query}", initial)
            if mode == "global_config":
                prompt, mode_raw = self._enter_ephemeral_config(ch, prompt)
                self.transcript.add(f"ENTER EPHEMERAL CONFIG [{query}]", mode_raw)
            elif mode != "privileged_exec":
                raise SafetyViolation(f"Unsupported discovery mode: {mode}")
            if mode == "privileged_exec" and "(config" in prompt:
                raise DiscoveryError(f"Unexpected config prompt: {prompt!r}")
            if mode == "global_config" and "(config" not in prompt:
                raise DiscoveryError(f"Expected config prompt: {prompt!r}")
            ch.send(query)
            self.help_queries += 1
            if shard:
                self.shard_queries += 1
            raw_help = self._read_quiet(ch, min(self.a.timeout, self.a.help_wait), self.a.quiet_time)
            self.transcript.add(f"HELP [{mode}] {query}", raw_help)
            ch.close()
            ch = None
            closed_immediately = True
            text = clean_terminal_text(raw_help)
            paginated = has_more_prompt(text)
            if paginated:
                self.pager_events += 1
            if any(x in text for x in ("Command too long", "% Unrecognized command", "% Invalid input")):
                raise DiscoveryError(f"Help query rejected: {query!r}: {text[-500:]}")
            self.audit.append(QueryAudit(mode, context_prefix, shard, query, prompt, paginated, 0, True, None))
            self._progress()
            self._checkpoint()
            time.sleep(max(0.0, self.a.delay))
            return self._parse_help(text, context_prefix, query), paginated
        except Exception as exc:
            self.errors.append({
                "mode": mode,
                "context_prefix": context_prefix,
                "shard": shard,
                "query": query,
                "error_type": type(exc).__name__,
                "error": str(exc),
            })
            self.audit.append(QueryAudit(
                mode, context_prefix, shard, query, prompt, paginated, 0,
                closed_immediately, f"{type(exc).__name__}: {exc}"
            ))
            self._progress()
            self._checkpoint()
            return [], False
        finally:
            if ch is not None:
                ch.close()

    def _collect_shards(self, mode: str, context_prefix: str, shard_prefix: str = "", level: int = 0) -> list[HelpItem]:
        if level >= self.a.max_shard_depth:
            self.errors.append({
                "mode": mode,
                "context_prefix": context_prefix,
                "shard": shard_prefix,
                "query": build_help_query(context_prefix, shard_prefix),
                "error_type": "ShardDepthLimit",
                "error": "Help remained paginated at maximum safe shard depth; no pager key was sent.",
            })
            return []
        merged: list[HelpItem] = []
        for char in SHARD_ALPHABET:
            shard = shard_prefix + char
            items, paginated = self.query_help_once(mode, context_prefix, shard)
            merged = merge_unique_items(merged, items)
            if paginated:
                merged = merge_unique_items(
                    merged,
                    self._collect_shards(mode, context_prefix, shard_prefix=shard, level=level + 1),
                )
        return merged

    def enumerate_help(self, mode: str, context_prefix: str) -> list[HelpItem]:
        items, paginated = self.query_help_once(mode, context_prefix)
        if not paginated:
            return items
        print(
            f"[+] Pager detected for {mode}:{context_prefix or '<root>'}; "
            "recovering hidden options with safe partial-keyword shards"
        )
        return merge_unique_items(items, self._collect_shards(mode, context_prefix))

    def crawl_children(self, mode: str, prefix: str, depth: int) -> dict[str, Any]:
        if depth > self.a.max_depth:
            return {"_meta": {"truncated": True, "reason": "max_depth"}}
        if self.nodes >= self.a.max_nodes:
            return {"_meta": {"truncated": True, "reason": "max_nodes"}}
        tree: dict[str, Any] = {}
        for item in self.enumerate_help(mode, prefix):
            self.nodes += 1
            node: dict[str, Any] = {
                "description": item.description,
                "kind": item.kind,
                "risk": item.risk,
                "children": {},
            }
            tree[item.token] = node
            if self.nodes >= self.a.max_nodes:
                node["children"] = {"_meta": {"truncated": True, "reason": "max_nodes"}}
                break
            if item.kind != "keyword" or depth >= self.a.max_depth:
                continue
            root = prefix.split()[0].lower() if prefix else item.token.lower()
            if root == "do" or item.token.lower() in NON_RECURSIVE_WRAPPERS:
                node["_meta"] = {"recursion_skipped": True, "reason": "duplicate_exec_wrapper"}
                continue
            child_prefix = f"{prefix} {item.token}" if prefix else item.token
            node["children"] = self.crawl_children(mode, child_prefix, depth + 1)
        return tree

    def crawl_mode(self, mode: str) -> dict[str, Any]:
        tree: dict[str, Any] = {}
        self.mode_trees[mode] = tree
        root_items = self.enumerate_help(mode, "")
        for item in root_items:
            self.nodes += 1
            node: dict[str, Any] = {
                "description": item.description,
                "kind": item.kind,
                "risk": item.risk,
                "children": {},
            }
            tree[item.token] = node
            if self.nodes >= self.a.max_nodes:
                node["children"] = {"_meta": {"truncated": True, "reason": "max_nodes"}}
                break
            if item.kind != "keyword" or self.a.max_depth <= 0:
                continue
            if item.token.lower() in NON_RECURSIVE_WRAPPERS:
                node["_meta"] = {
                    "recursion_skipped": True,
                    "reason": "duplicate_exec_wrapper",
                    "alias_of": "privileged_exec_tree",
                }
                continue
            node["children"] = self.crawl_children(mode, item.token, depth=1)
            self._checkpoint()
        return tree

    def run(self) -> dict[str, Any]:
        for command in sorted(READ_ONLY_EXEC_ALLOWLIST):
            try:
                self.inventory[command] = self.execute_read_only(command)
            except Exception as exc:
                self.errors.append({
                    "mode": "inventory",
                    "context_prefix": command,
                    "shard": "",
                    "query": command,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                })
        self.mode_trees["privileged_exec"] = self.crawl_mode("privileged_exec")
        if self.a.include_config_help:
            self.mode_trees["global_config"] = self.crawl_mode("global_config")
        return self.build_document(status="COMPLETE")

    def build_document(self, status: str) -> dict[str, Any]:
        return {
            "schema_version": 4,
            "tool_version": VERSION,
            "generated_at_utc": utc_now(),
            "status": status,
            "device": {
                "host": self.a.host,
                "port": self.a.port,
                "username": self.a.username,
                "ssh_host_key": self.host_key,
            },
            "safety_contract": {
                "mode": "INVESTIGATION_ONLY",
                "discovered_commands_executed": False,
                "help_query_submitted_with_enter": False,
                "bytes_sent_after_help_marker_per_query": 0,
                "disposable_channel_per_help_query": True,
                "pager_navigation_after_help_query": False,
                "ctrl_c_after_help_query": False,
                "enter_after_help_query": False,
                "hard_deny_exec_roots": sorted(HARD_DENY_EXEC_ROOTS),
                "exact_read_only_exec_allowlist": sorted(READ_ONLY_EXEC_ALLOWLIST),
                "global_config_help_enabled": self.a.include_config_help,
                "global_config_changes_allowed": False,
                "config_submode_transitions_allowed": False,
            },
            "scope": {
                "one_run_full_safe": self.a.full_safe,
                "privileged_exec_grammar": True,
                "global_config_grammar": self.a.include_config_help,
                "partial_keyword_sharding_for_pagination": True,
                "dynamic_placeholder_values_instantiated": False,
                "configuration_submodes_entered": False,
                "note": (
                    "The crawler exhausts safely discoverable context-help grammar without executing "
                    "discovered commands. It intentionally does not instantiate dynamic values or "
                    "enter potentially state-changing configuration submodes."
                ),
            },
            "limits": {
                "max_depth": self.a.max_depth,
                "max_nodes": self.a.max_nodes,
                "max_shard_depth": self.a.max_shard_depth,
                "delay_seconds": self.a.delay,
                "transport_recycle_every_queries": self.a.transport_recycle,
            },
            "inventory": self.inventory,
            "modes": {name: {"tree": tree} for name, tree in self.mode_trees.items()},
            "crawler": {
                "nodes_found": self.nodes,
                "help_queries": self.help_queries,
                "pager_events": self.pager_events,
                "shard_queries": self.shard_queries,
                "transport_recycles": self.transport_recycles,
                "errors": self.errors,
                "query_audit": [
                    {
                        "mode": q.mode,
                        "context_prefix": q.context_prefix,
                        "shard": q.shard,
                        "query": q.query,
                        "prompt": q.prompt,
                        "paginated": q.paginated,
                        "bytes_sent_after_help_marker": q.bytes_sent_after_help_marker,
                        "channel_closed_immediately": q.channel_closed_immediately,
                        "error": q.error,
                    }
                    for q in self.audit
                ],
            },
        }


def build_summary(document: dict[str, Any]) -> dict[str, Any]:
    modes: dict[str, Any] = {}
    for name, data in document.get("modes", {}).items():
        tree = data.get("tree", {})
        top = [k for k in tree if k != "_meta"]
        modes[name] = {"top_level_count": len(top), "top_level_commands": top}
    return {
        "tool_version": document["tool_version"],
        "generated_at_utc": document["generated_at_utc"],
        "status": document["status"],
        "device": document["device"],
        "safety_contract": document["safety_contract"],
        "scope": document["scope"],
        "nodes_found": document["crawler"]["nodes_found"],
        "help_queries": document["crawler"]["help_queries"],
        "pager_events": document["crawler"]["pager_events"],
        "shard_queries": document["crawler"]["shard_queries"],
        "transport_recycles": document["crawler"]["transport_recycles"],
        "errors": len(document["crawler"]["errors"]),
        "modes": modes,
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="CBS250/CBS350 safe CLI capability discovery v3.1; investigation only"
    )
    p.add_argument("--host")
    p.add_argument("--username", default="admin")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--max-depth", type=int, default=7)
    p.add_argument("--max-nodes", type=int, default=8000)
    p.add_argument("--max-shard-depth", type=int, default=4)
    p.add_argument("--delay", type=float, default=0.05)
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--help-wait", type=float, default=4.0)
    p.add_argument("--quiet-time", type=float, default=0.45)
    p.add_argument("--output-dir", default="")
    p.add_argument("--password-env", default="CBS_PASSWORD")
    p.add_argument("--progress-every", type=int, default=20)
    p.add_argument("--checkpoint-every", type=int, default=50)
    p.add_argument("--transport-recycle", type=int, default=120)
    p.add_argument("--reconnect-backoff", type=float, default=1.0)
    p.add_argument("--channel-open-attempts", type=int, default=3)
    p.add_argument("--include-config-help", action="store_true")
    p.add_argument(
        "--full-safe",
        action="store_true",
        help=(
            "One-run maximum safe discovery: privileged EXEC plus global-config grammar, "
            "automatic pagination sharding, progress, and checkpoints. Dynamic placeholder "
            "values/config submodes are not instantiated."
        ),
    )
    p.add_argument("--policy-check", action="store_true")
    return p.parse_args()


def policy_check() -> int:
    forbidden = (
        "delete flash:test",
        "clear logging",
        "clear logging file",
        "reload",
        "boot system inactive-image",
        "copy running-config startup-config",
        "write memory",
        "configure terminal",
        "set system mode",
        "no logging",
        "shutdown",
        "crypto key generate rsa",
    )
    for command in forbidden:
        try:
            assert_read_only_executable(command)
        except SafetyViolation:
            continue
        raise AssertionError(f"Forbidden command accepted: {command}")
    for command in READ_ONLY_EXEC_ALLOWLIST:
        assert assert_read_only_executable(command) == command
    assert build_help_query("", "") == "?"
    assert build_help_query("show", "") == "show ?"
    assert build_help_query("", "s") == "s?"
    assert build_help_query("show", "s") == "show s?"
    assert has_more_prompt("More: <space>,  Quit: q or CTRL+Z, One line: <return>")
    print(f"[PASS] CBS250 discovery safety policy v{VERSION}")
    print("[PASS] Destructive/state-changing generic execution is hard blocked")
    print("[PASS] Sharded help queries contain no CR/LF and require no pager key")
    return 0


def write_outputs(out_dir: Path, document: dict[str, Any], transcript: str) -> None:
    (out_dir / "cbs250_command_tree_v31.json").write_text(
        json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (out_dir / "cbs250_capability_summary_v31.json").write_text(
        json.dumps(build_summary(document), indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (out_dir / "cbs250_raw_transcript_v31.txt").write_text(transcript, encoding="utf-8")


def main() -> int:
    args = parse_args()
    if args.policy_check:
        return policy_check()
    if not args.host:
        print("ERROR: --host is required unless --policy-check is used", file=sys.stderr)
        return 2
    if args.full_safe:
        args.include_config_help = True
        args.max_nodes = max(args.max_nodes, 12000)
    password = os.getenv(args.password_env)
    if password is None:
        password = getpass.getpass(f"SSH password for {args.username}@{args.host}: ")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = (
        Path(args.output_dir).expanduser().resolve()
        if args.output_dir
        else Path.home() / "Downloads" / f"CBS250_CLI_Discovery_v31_{stamp}"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    crawler = CBS250ReadOnlyCrawler(args, password, out_dir)
    document: Optional[dict[str, Any]] = None
    rc = 0
    print(f"[SAFETY] CBS250 discovery v{VERSION}: INVESTIGATION_ONLY")
    print("[SAFETY] Discovered commands are NEVER executed")
    print("[SAFETY] After '?' the channel receives ZERO additional bytes")
    print("[SAFETY] Pager output is recovered by NEW partial-keyword channels, never Space/Enter")
    print("[SAFETY] delete/clear/reload/boot/copy/write/config execution is hard blocked")
    print(
        "[SCOPE] " + (
            "FULL_SAFE one-run: EXEC + global-config grammar"
            if args.full_safe
            else "EXEC grammar" + (" + global-config grammar" if args.include_config_help else "")
        )
    )
    try:
        print(f"[+] Connecting to {args.host}:{args.port}")
        crawler.connect()
        print(f"[+] SSH host key: {crawler.host_key['type']} {crawler.host_key['bits']} bits")
        document = crawler.run()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user; writing partial evidence", file=sys.stderr)
        document = crawler.build_document(status="INTERRUPTED")
        rc = 130
    except Exception as exc:
        print(f"[!] FAIL-CLOSED: {type(exc).__name__}: {exc}", file=sys.stderr)
        crawler.errors.append({
            "mode": "runtime",
            "context_prefix": "",
            "shard": "",
            "query": crawler.current_query,
            "error_type": type(exc).__name__,
            "error": str(exc),
        })
        document = crawler.build_document(status="FAILED_CLOSED")
        rc = 1
    finally:
        crawler.close()
    assert document is not None
    write_outputs(out_dir, document, crawler.transcript.text())
    print(f"[+] Output: {out_dir}")
    print(f"[+] Status: {document['status']}")
    print(f"[+] Nodes found: {document['crawler']['nodes_found']}")
    print(f"[+] Help queries: {document['crawler']['help_queries']}")
    print(f"[+] Pager events: {document['crawler']['pager_events']}")
    print(f"[+] Shard queries: {document['crawler']['shard_queries']}")
    print(f"[+] Errors: {len(document['crawler']['errors'])}")
    print("[+] Safety audit: zero bytes sent after every '?' help marker")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
