import socket

import paramiko
import pytest

from cisco_assistant.read_only_transport import (
    ParamikoCBS250ReadOnlySession,
    ReadOnlySessionError,
    ReadOnlySessionErrorCode,
    SessionCredentials,
)


class FakeSecurityOptions:
    def __init__(self):
        self.key_types = ("ssh-ed25519", "ssh-dss")


class FakeKey:
    def get_name(self):
        return "ssh-rsa"

    def get_bits(self):
        return 2048

    def asbytes(self):
        return b"fake-host-key"


class FakeSocket:
    def close(self):
        pass


class FakeAuthFailureTransport:
    def __init__(self, _sock):
        self.security = FakeSecurityOptions()
        self.closed = False

    def get_security_options(self):
        return self.security

    def start_client(self, timeout=None):
        return None

    def get_remote_server_key(self):
        return FakeKey()

    def auth_password(self, _username, _password, fallback=False):
        raise paramiko.AuthenticationException("synthetic auth failure")

    def auth_interactive(self, _username, _handler):
        raise paramiko.AuthenticationException("synthetic interactive failure")

    def is_authenticated(self):
        return False

    def close(self):
        self.closed = True


def test_unreachable_ssh_has_stable_safe_error(monkeypatch):
    secret = "never-emit-this-password"
    username = "private-operator-name"

    def fail_connect(*_args, **_kwargs):
        raise OSError("synthetic connection refused")

    monkeypatch.setattr(socket, "create_connection", fail_connect)
    session = ParamikoCBS250ReadOnlySession(
        "192.0.2.1",
        SessionCredentials(username=username, password=secret),
    )

    with pytest.raises(ReadOnlySessionError) as caught:
        session.connect()

    assert caught.value.code is ReadOnlySessionErrorCode.CONNECTION_FAILED
    rendered = str(caught.value)
    assert secret not in rendered
    assert username not in rendered


def test_wrong_password_has_stable_safe_error_and_disables_dss(monkeypatch):
    secret = "wrong-password-never-emit"
    username = "private-admin"
    created = []

    monkeypatch.setattr(socket, "create_connection", lambda *_a, **_k: FakeSocket())

    def make_transport(sock):
        transport = FakeAuthFailureTransport(sock)
        created.append(transport)
        return transport

    monkeypatch.setattr(paramiko, "Transport", make_transport)
    session = ParamikoCBS250ReadOnlySession(
        "192.0.2.2",
        SessionCredentials(username=username, password=secret),
    )

    with pytest.raises(ReadOnlySessionError) as caught:
        session.connect()

    assert caught.value.code is ReadOnlySessionErrorCode.AUTHENTICATION_FAILED
    rendered = str(caught.value)
    assert secret not in rendered
    assert username not in rendered
    assert created
    assert "ssh-dss" not in created[0].security.key_types
    assert "ssh-rsa" in created[0].security.key_types
