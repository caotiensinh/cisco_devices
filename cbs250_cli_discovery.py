#!/usr/bin/env python3
"""
CBS250 CLI Capability Discovery v3 -- INVESTIGATION ONLY.

Core invariant:
    one '?' help query == one disposable SSH shell channel

After the literal '?' is sent, v3 sends ZERO more bytes on that channel. It does
not send Enter, Ctrl-C, a sync sequence, or another command. The channel is read
until quiet and then destroyed.

Discovered commands are data only and are never executed.
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
    prefix: str
    prompt: str
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
        self.parts.append(f"\n===== {utc_now()} | {label} =====\n{clean_terminal_text(raw)}\n")
    def text(self) -> str:
        return "".join(self.parts)

class CBS250ReadOnlyCrawler:
    def __init__(self, args: argparse.Namespace, password: str) -> None:
        self.a = args
        self.password = password
        self.transport: Optional[paramiko.Transport] = None
        self.transcript = Transcript()
        self.nodes = 0
        self.help_queries = 0
        self.errors: list[dict[str, Any]] = []
        self.audit: list[QueryAudit] = []
        self.visited: set[tuple[str, str]] = set()
        self.host_key = {"type": "", "bits": 0, "fingerprint": ""}

    def connect(self) -> None:
        sock = socket.create_connection((self.a.host, self.a.port), timeout=self.a.timeout)
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
                "type": key.get_name(), "bits": key.get_bits(),
                "fingerprint": ssh_fingerprint(key),
            }
            self.transcript.add("SSH NEGOTIATION", json.dumps(self.host_key, indent=2))
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
                        f"prompts={prompts!r}; password_error={password_error}; interactive_error={exc}"
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

    def _new_shell(self) -> "paramiko.Channel":
        if self.transport is None or not self.transport.is_authenticated():
            raise DiscoveryError("SSH transport is not authenticated")
        ch = self.transport.open_session(timeout=self.a.timeout)
        ch.get_pty(term="vt100", width=240, height=2000)
        ch.invoke_shell()
        ch.settimeout(0.25)
        return ch

    def _read_quiet(self, ch: "paramiko.Channel", max_wait: float, quiet: float = 0.50) -> str:
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
            ch, prompt, initial = self._fresh_exec_shell()
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

    def query_help(self, mode: str, prefix: str) -> list[HelpItem]:
        prefix = normalize_command(prefix)
        key = (mode, prefix)
        if key in self.visited:
            return []
        self.visited.add(key)
        ch: Optional[paramiko.Channel] = None
        prompt = ""
        raw_help = ""
        closed_immediately = False
        try:
            ch, prompt, initial = self._fresh_exec_shell()
            self.transcript.add(f"HELP INITIAL [{mode}] {prefix or '<root>'}", initial)
            if mode == "global_config":
                prompt, mode_raw = self._enter_ephemeral_config(ch, prompt)
                self.transcript.add(f"ENTER EPHEMERAL CONFIG {prefix or '<root>'}", mode_raw)
            elif mode != "privileged_exec":
                raise SafetyViolation(f"Unsupported discovery mode: {mode}")
            if mode == "privileged_exec" and "(config" in prompt:
                raise DiscoveryError(f"Unexpected config prompt: {prompt!r}")
            if mode == "global_config" and "(config" not in prompt:
                raise DiscoveryError(f"Expected config prompt: {prompt!r}")
            query = "?" if not prefix else f"{prefix} ?"
            if "\r" in query or "\n" in query:
                raise SafetyViolation("Help query contains a line terminator")
            ch.send(query)
            self.help_queries += 1
            raw_help = self._read_quiet(ch, min(self.a.timeout, 5.0), self.a.quiet_time)
            self.transcript.add(f"HELP [{mode}] {query}", raw_help)
            ch.close()
            ch = None
            closed_immediately = True
            text = clean_terminal_text(raw_help)
            if any(x in text for x in ("Command too long", "% Unrecognized command", "% Invalid input")):
                raise DiscoveryError(f"Help query rejected: {query!r}: {text[-500:]}")
            self.audit.append(QueryAudit(mode, prefix, prompt, 0, True, None))
            time.sleep(max(0.0, self.a.delay))
            return self._parse_help(text, prefix)
        except Exception as exc:
            self.errors.append({
                "mode": mode, "prefix": prefix,
                "error_type": type(exc).__name__, "error": str(exc),
            })
            self.audit.append(QueryAudit(mode, prefix, prompt, 0, closed_immediately,
                                         f"{type(exc).__name__}: {exc}"))
            return []
        finally:
            if ch is not None:
                ch.close()

    def _parse_help(self, text: str, prefix: str) -> list[HelpItem]:
        result: list[HelpItem] = []
        seen: set[str] = set()
        query = "?" if not prefix else f"{prefix} ?"
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped == query or stripped.endswith(query):
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
            root = (prefix.split()[0] if prefix else token).lower()
            result.append(HelpItem(token, desc, kind, ROOT_RISK.get(root, "unknown")))
        return result

    def crawl(self, mode: str, prefix: str = "", depth: int = 0) -> dict[str, Any]:
        if depth > self.a.max_depth:
            return {"_meta": {"truncated": True, "reason": "max_depth"}}
        if self.nodes >= self.a.max_nodes:
            return {"_meta": {"truncated": True, "reason": "max_nodes"}}
        tree: dict[str, Any] = {}
        for item in self.query_help(mode, prefix):
            self.nodes += 1
            node = {
                "description": item.description, "kind": item.kind,
                "risk": item.risk, "children": {},
            }
            tree[item.token] = node
            if self.nodes >= self.a.max_nodes:
                node["children"] = {"_meta": {"truncated": True, "reason": "max_nodes"}}
                break
            if item.kind == "keyword" and depth < self.a.max_depth:
                child = item.token if not prefix else f"{prefix} {item.token}"
                node["children"] = self.crawl(mode, child, depth + 1)
        return tree

    def run(self) -> dict[str, Any]:
        inventory: dict[str, str] = {}
        for cmd in sorted(READ_ONLY_EXEC_ALLOWLIST):
            try:
                inventory[cmd] = self.execute_read_only(cmd)
            except Exception as exc:
                self.errors.append({"mode": "inventory", "prefix": cmd,
                                    "error_type": type(exc).__name__, "error": str(exc)})
        modes: dict[str, Any] = {
            "privileged_exec": {"tree": self.crawl("privileged_exec")}
        }
        if self.a.include_config_help:
            modes["global_config"] = {"tree": self.crawl("global_config")}
        return {
            "schema_version": 3,
            "tool_version": VERSION,
            "generated_at_utc": utc_now(),
            "device": {
                "host": self.a.host, "port": self.a.port, "username": self.a.username,
                "ssh_host_key": self.host_key,
            },
            "safety_contract": {
                "mode": "INVESTIGATION_ONLY",
                "discovered_commands_executed": False,
                "help_query_submitted_with_enter": False,
                "bytes_sent_after_help_marker_per_query": 0,
                "disposable_channel_per_help_query": True,
                "ctrl_c_after_help_query": False,
                "enter_after_help_query": False,
                "hard_deny_exec_roots": sorted(HARD_DENY_EXEC_ROOTS),
                "exact_read_only_exec_allowlist": sorted(READ_ONLY_EXEC_ALLOWLIST),
                "global_config_help_enabled": bool(self.a.include_config_help),
                "global_config_changes_allowed": False,
            },
            "limits": {
                "max_depth": self.a.max_depth, "max_nodes": self.a.max_nodes,
                "delay_seconds": self.a.delay,
            },
            "inventory": inventory,
            "modes": modes,
            "crawler": {
                "nodes_found": self.nodes, "help_queries": self.help_queries,
                "errors": self.errors,
                "query_audit": [q.__dict__ for q in self.audit],
            },
        }

def build_summary(doc: dict[str, Any]) -> dict[str, Any]:
    modes = {}
    for name, data in doc.get("modes", {}).items():
        tree = data.get("tree", {})
        top = [k for k in tree if k != "_meta"]
        modes[name] = {"top_level_count": len(top), "top_level_commands": top}
    return {
        "tool_version": doc["tool_version"], "generated_at_utc": doc["generated_at_utc"],
        "device": doc["device"], "safety_contract": doc["safety_contract"],
        "nodes_found": doc["crawler"]["nodes_found"],
        "help_queries": doc["crawler"]["help_queries"],
        "errors": len(doc["crawler"]["errors"]), "modes": modes,
    }

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="CBS250/CBS350 investigation-only CLI discovery v3")
    p.add_argument("--host")
    p.add_argument("--username", default="admin")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--quiet-time", type=float, default=0.50)
    p.add_argument("--max-depth", type=int, default=5)
    p.add_argument("--max-nodes", type=int, default=1500)
    p.add_argument("--delay", type=float, default=0.10)
    p.add_argument("--output-dir", default="")
    p.add_argument("--password-env", default="CBS_PASSWORD")
    p.add_argument("--include-config-help", action="store_true",
                   help="Opt-in ephemeral global-config '?' discovery; no config command is executed")
    p.add_argument("--policy-check", action="store_true",
                   help="Print execution policy and exit without connecting")
    return p.parse_args()

def policy_check() -> None:
    print(f"CBS250 discovery v{VERSION}: INVESTIGATION_ONLY")
    print("Exact read-only executable allowlist:")
    for x in sorted(READ_ONLY_EXEC_ALLOWLIST):
        print("  ALLOW:", x)
    print("Hard-denied execution roots:")
    for x in sorted(HARD_DENY_EXEC_ROOTS):
        print("  DENY:", x)

def main() -> int:
    a = parse_args()
    if a.policy_check:
        policy_check(); return 0
    if not a.host:
        print("ERROR: --host is required unless --policy-check is used", file=sys.stderr)
        return 2
    password = os.getenv(a.password_env) or getpass.getpass(f"SSH password for {a.username}@{a.host}: ")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = (Path(a.output_dir).expanduser().resolve() if a.output_dir else
           Path.home()/"Downloads"/f"CBS250_CLI_Discovery_v3_{stamp}")
    out.mkdir(parents=True, exist_ok=True)
    c = CBS250ReadOnlyCrawler(a, password)
    try:
        print("[SAFETY] INVESTIGATION_ONLY")
        print("[SAFETY] Discovered commands are NEVER executed")
        print("[SAFETY] One '?' query = one disposable SSH channel")
        print("[SAFETY] Zero bytes are sent after '?' on that channel")
        print("[SAFETY] Global config help:", "ENABLED" if a.include_config_help else "DISABLED")
        print(f"[+] Connecting to {a.host}:{a.port}")
        c.connect()
        print(f"[+] SSH host key: {c.host_key['type']} {c.host_key['bits']} {c.host_key['fingerprint']}")
        doc = c.run()
    except KeyboardInterrupt:
        print("[!] Interrupted", file=sys.stderr); return 130
    except Exception as exc:
        print(f"[!] FAIL-CLOSED: {type(exc).__name__}: {exc}", file=sys.stderr); return 1
    finally:
        c.close()
    tree = out/"cbs250_command_tree_v3.json"
    summary = out/"cbs250_capability_summary_v3.json"
    transcript = out/"cbs250_raw_transcript_v3.txt"
    tree.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
    summary.write_text(json.dumps(build_summary(doc), indent=2, ensure_ascii=False), encoding="utf-8")
    transcript.write_text(c.transcript.text(), encoding="utf-8")
    print(f"[+] Output: {out}")
    print(f"[+] Nodes found: {doc['crawler']['nodes_found']}")
    print(f"[+] Help queries: {doc['crawler']['help_queries']}")
    print(f"[+] Errors: {len(doc['crawler']['errors'])}")
    print("[+] DONE: no discovered command was executed")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
