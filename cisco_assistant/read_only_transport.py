"""Credential-scoped, exact-allowlist read-only SSH transport for CBS250.

This module is the only P2 component allowed to submit CLI commands. Every submitted command
must pass ``cbs250_safety.assert_read_only_executable``. It does not expose configuration mode,
raw shell access, arbitrary command execution, pager continuation, or persistence APIs.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from enum import Enum
import hashlib
import socket
import time
from typing import Iterable

import paramiko

from cbs250_safety import SafetyViolation, assert_read_only_executable


class ReadOnlySessionErrorCode(str, Enum):
    CONNECTION_FAILED = "connection_failed"
    AUTHENTICATION_FAILED = "authentication_failed"
    HOST_KEY_MISMATCH = "host_key_mismatch"
    PROMPT_NOT_ESTABLISHED = "prompt_not_established"
    COMMAND_REJECTED = "command_rejected"
    PAGINATION_DETECTED = "pagination_detected"
    TRANSPORT_FAILED = "transport_failed"


class ReadOnlySessionError(RuntimeError):
    """Safe operational error that never embeds supplied credentials."""

    def __init__(self, code: ReadOnlySessionErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True, repr=False)
class SessionCredentials:
    username: str
    password: str

    def __post_init__(self) -> None:
        if not self.username.strip():
            raise ValueError("username must not be empty")
        if not self.password:
            raise ValueError("password must not be empty")

    def __repr__(self) -> str:
        return "SessionCredentials(username=<redacted>, password=<redacted>)"

    def safe_metadata(self) -> dict[str, object]:
        return {
            "credential_type": "username_password",
            "username_present": bool(self.username),
            "password_present": bool(self.password),
            "secret_values_exported": False,
        }


@dataclass(frozen=True, slots=True)
class ReadOnlyCommandResult:
    command: str
    output: str
    prompt: str
    duration_ms: int


@dataclass(frozen=True, slots=True)
class SSHPeerIdentity:
    key_type: str
    bits: int
    sha256_fingerprint: str

    def safe_metadata(self, *, include_fingerprint: bool = False) -> dict[str, object]:
        result: dict[str, object] = {
            "key_type": self.key_type,
            "bits": self.bits,
        }
        if include_fingerprint:
            result["sha256_fingerprint"] = self.sha256_fingerprint
        return result


def _fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _clean_terminal_text(text: str) -> str:
    # Keep this deliberately small: command parsers tolerate echoes/prompts. The transport's
    # job is containment, not interpretation.
    return text.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n")


class ParamikoCBS250ReadOnlySession:
    """One authenticated SSH transport with a disposable shell per allowlisted R0 command."""

    def __init__(
        self,
        host: str,
        credentials: SessionCredentials,
        *,
        port: int = 22,
        timeout: float = 8.0,
        quiet_time: float = 0.35,
        expected_host_key_sha256: str | None = None,
    ) -> None:
        if not host.strip():
            raise ValueError("host must not be empty")
        if not 1 <= port <= 65535:
            raise ValueError("port must be inside 1..65535")
        self.host = host.strip()
        self.port = port
        self.credentials = credentials
        self.timeout = timeout
        self.quiet_time = quiet_time
        self.expected_host_key_sha256 = expected_host_key_sha256
        self._transport: paramiko.Transport | None = None
        self.peer_identity: SSHPeerIdentity | None = None

    def __enter__(self) -> "ParamikoCBS250ReadOnlySession":
        self.connect()
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.close()

    @property
    def connected(self) -> bool:
        return bool(self._transport and self._transport.is_authenticated())

    def connect(self) -> None:
        self.close()
        sock: socket.socket | None = None
        transport: paramiko.Transport | None = None
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            transport = paramiko.Transport(sock)
            sock = None  # owned by Paramiko from this point

            security = transport.get_security_options()
            key_types = [name for name in security.key_types if name != "ssh-dss"]
            if "ssh-rsa" not in key_types:
                key_types.append("ssh-rsa")
            security.key_types = tuple(key_types)

            transport.start_client(timeout=self.timeout)
            key = transport.get_remote_server_key()
            peer = SSHPeerIdentity(
                key_type=key.get_name(),
                bits=key.get_bits(),
                sha256_fingerprint=_fingerprint(key),
            )
            if (
                self.expected_host_key_sha256 is not None
                and peer.sha256_fingerprint != self.expected_host_key_sha256
            ):
                raise ReadOnlySessionError(
                    ReadOnlySessionErrorCode.HOST_KEY_MISMATCH,
                    "SSH host key does not match the expected fingerprint.",
                )

            password_error: Exception | None = None
            try:
                transport.auth_password(
                    self.credentials.username,
                    self.credentials.password,
                    fallback=False,
                )
            except paramiko.AuthenticationException as exc:
                password_error = exc

            if not transport.is_authenticated():
                def handler(_title: str, _instructions: str, questions: Iterable) -> list[str]:
                    prompts = list(questions)
                    return [
                        self.credentials.password
                        if "password" in str(prompt).lower() or len(prompts) == 1
                        else ""
                        for prompt, _echo in prompts
                    ]

                try:
                    transport.auth_interactive(self.credentials.username, handler)
                except paramiko.AuthenticationException as exc:
                    raise ReadOnlySessionError(
                        ReadOnlySessionErrorCode.AUTHENTICATION_FAILED,
                        "SSH authentication failed.",
                    ) from exc

            if not transport.is_authenticated():
                raise ReadOnlySessionError(
                    ReadOnlySessionErrorCode.AUTHENTICATION_FAILED,
                    "SSH authentication was not established.",
                ) from password_error

            self.peer_identity = peer
            self._transport = transport
        except ReadOnlySessionError:
            if transport is not None:
                transport.close()
            if sock is not None:
                sock.close()
            raise
        except (OSError, paramiko.SSHException) as exc:
            if transport is not None:
                transport.close()
            if sock is not None:
                sock.close()
            raise ReadOnlySessionError(
                ReadOnlySessionErrorCode.CONNECTION_FAILED,
                "Unable to establish the SSH read-only session.",
            ) from exc

    def close(self) -> None:
        if self._transport is not None:
            try:
                self._transport.close()
            finally:
                self._transport = None

    def _read_quiet(self, channel: paramiko.Channel, max_wait: float) -> str:
        chunks: list[str] = []
        start = last = time.monotonic()
        while time.monotonic() - start < max_wait:
            got = False
            try:
                while channel.recv_ready():
                    data = channel.recv(65535)
                    if not data:
                        break
                    chunks.append(data.decode("utf-8", errors="replace"))
                    last = time.monotonic()
                    got = True
            except socket.timeout:
                pass
            if chunks and time.monotonic() - last >= self.quiet_time:
                break
            if not got:
                time.sleep(0.03)
        return "".join(chunks)

    @staticmethod
    def _extract_prompt(raw: str) -> str:
        lines = [line.strip() for line in _clean_terminal_text(raw).splitlines() if line.strip()]
        candidates = [line for line in lines if line.endswith(("#", ">")) and len(line) <= 160]
        return candidates[-1] if candidates else ""

    def execute(self, command: str) -> ReadOnlyCommandResult:
        # Policy validation happens before any network/channel activity for the command.
        normalized = assert_read_only_executable(command)
        if self._transport is None or not self._transport.is_authenticated():
            raise ReadOnlySessionError(
                ReadOnlySessionErrorCode.TRANSPORT_FAILED,
                "Read-only SSH session is not connected.",
            )

        channel: paramiko.Channel | None = None
        started = time.monotonic()
        try:
            channel = self._transport.open_session(timeout=self.timeout)
            channel.get_pty(term="vt100", width=240, height=2000)
            channel.invoke_shell()
            channel.settimeout(0.25)

            initial = self._read_quiet(channel, self.timeout)
            prompt = self._extract_prompt(initial)
            if not prompt:
                # A blank CR is permitted only to expose the existing EXEC prompt. No CLI
                # command text is present, and the channel remains disposable.
                channel.send("\r")
                initial += self._read_quiet(channel, min(3.0, self.timeout))
                prompt = self._extract_prompt(initial)
            if not prompt or "(config" in prompt.lower():
                raise ReadOnlySessionError(
                    ReadOnlySessionErrorCode.PROMPT_NOT_ESTABLISHED,
                    "A clean privileged/EXEC prompt was not established.",
                )

            channel.send(normalized + "\r")
            raw = self._read_quiet(channel, self.timeout)
            text = _clean_terminal_text(raw)
            lowered = text.lower()

            if "more:" in lowered or "--more--" in lowered:
                # Never navigate a pager in this collector. Add a reviewed, non-paginating
                # collector strategy before expanding the allowlist.
                raise ReadOnlySessionError(
                    ReadOnlySessionErrorCode.PAGINATION_DETECTED,
                    f"Read-only command {normalized!r} paginated; collection stopped.",
                )
            if any(
                marker in text
                for marker in ("% Unrecognized command", "% Invalid input", "Command too long")
            ):
                raise ReadOnlySessionError(
                    ReadOnlySessionErrorCode.COMMAND_REJECTED,
                    f"Read-only command {normalized!r} was rejected by the device.",
                )

            return ReadOnlyCommandResult(
                command=normalized,
                output=text,
                prompt=prompt,
                duration_ms=max(0, int((time.monotonic() - started) * 1000)),
            )
        except SafetyViolation:
            raise
        except ReadOnlySessionError:
            raise
        except (OSError, paramiko.SSHException) as exc:
            raise ReadOnlySessionError(
                ReadOnlySessionErrorCode.TRANSPORT_FAILED,
                f"SSH transport failed while collecting {normalized!r}.",
            ) from exc
        finally:
            if channel is not None:
                channel.close()
