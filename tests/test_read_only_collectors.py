from cbs250_safety import SafetyViolation
from cisco_assistant.read_only_collectors import (
    COLLECTOR_COMMANDS,
    collect_cbs250_inventory,
    parse_show_ip_ssh,
    parse_show_system,
    parse_show_version,
)
from cisco_assistant.read_only_transport import (
    ParamikoCBS250ReadOnlySession,
    ReadOnlyCommandResult,
    ReadOnlySessionError,
    ReadOnlySessionErrorCode,
    SessionCredentials,
)


SHOW_SYSTEM = """
show system
System Description: CBS250-24T-4X 24-Port Gigabit Smart Switch with 10G Uplinks
System Name: example-switch
System MAC Address: 00:11:22:33:44:55
System Type: CBS250-24T-4X
Temperature: 52 C
Temperature Status: OK
example-switch#
"""

SHOW_VERSION = """
show version
Active-image:
  Version: 3.3.0.16
  Date: 23-Mar-2023
Inactive-image:
  Version: 3.3.0.16
example-switch#
"""

SHOW_IP_SSH = """
show ip ssh
SSH Server: Enabled
Password Authentication: Enabled
Public Key Authentication: Disabled
example-switch#
"""


class FakeExecutor:
    def __init__(self, outputs):
        self.outputs = outputs
        self.calls = []

    def execute(self, command):
        self.calls.append(command)
        value = self.outputs[command]
        if isinstance(value, Exception):
            raise value
        return ReadOnlyCommandResult(
            command=command,
            output=value,
            prompt="example-switch#",
            duration_ms=5,
        )


def test_parsers_extract_exact_identity_and_ssh_state():
    system = parse_show_system(SHOW_SYSTEM)
    version = parse_show_version(SHOW_VERSION)
    ssh = parse_show_ip_ssh(SHOW_IP_SSH)

    assert system["product_id"] == "CBS250-24T-4X"
    assert system["system_description"].startswith("CBS250-24T-4X")
    assert system["temperature_celsius"] == 52
    assert system["temperature_status"] == "OK"
    assert version["firmware_version"] == "3.3.0.16"
    assert ssh.server_enabled is True
    assert ssh.password_authentication_enabled is True
    assert ssh.public_key_authentication_enabled is False


def test_collector_runs_only_reviewed_commands_and_returns_partial_state():
    executor = FakeExecutor(
        {
            "show system": SHOW_SYSTEM,
            "show version": SHOW_VERSION,
            "show ip ssh": SHOW_IP_SSH,
        }
    )
    snapshot = collect_cbs250_inventory(
        executor,
        source_revision="unit-test",
        collected_at_utc="2026-08-25T14:00:00+00:00",
    )

    assert tuple(executor.calls) == COLLECTOR_COMMANDS
    assert snapshot.fingerprint is not None
    assert snapshot.fingerprint.product_id == "CBS250-24T-4X"
    assert snapshot.fingerprint.firmware_version == "3.3.0.16"
    assert snapshot.observed_state is not None
    assert snapshot.observed_state.partial is True
    assert snapshot.current_network_state is not None
    assert snapshot.current_network_state.basis.value == "observed_partial"
    assert snapshot.current_network_state.absence_is_authoritative is False
    assert snapshot.current_network_state.management.services == ("ssh",)
    assert snapshot.complete_for_planner_scope is False
    assert snapshot.device_write_authority is False


def test_safe_export_contains_no_raw_outputs_or_operational_identifiers():
    executor = FakeExecutor(
        {
            "show system": SHOW_SYSTEM,
            "show version": SHOW_VERSION,
            "show ip ssh": SHOW_IP_SSH,
        }
    )
    snapshot = collect_cbs250_inventory(executor, source_revision="unit-test")
    payload = snapshot.as_safe_dict()
    rendered = repr(payload)

    assert payload["credentials_exported"] is False
    assert payload["raw_command_output_exported"] is False
    assert "00:11:22:33:44:55" not in rendered
    assert "example-switch" not in rendered
    assert "super-secret-value" not in rendered


def test_missing_identity_withholds_planner_state_instead_of_guessing():
    executor = FakeExecutor(
        {
            "show system": "System Description: unknown\n",
            "show version": SHOW_VERSION,
            "show ip ssh": SHOW_IP_SSH,
        }
    )
    snapshot = collect_cbs250_inventory(executor, source_revision="unit-test")

    assert snapshot.fingerprint is None
    assert snapshot.observed_state is None
    assert snapshot.current_network_state is None
    assert any(error.code == "identity_incomplete" for error in snapshot.errors)


def test_partial_command_failure_is_explicit_and_does_not_make_absence_authoritative():
    executor = FakeExecutor(
        {
            "show system": SHOW_SYSTEM,
            "show version": SHOW_VERSION,
            "show ip ssh": ReadOnlySessionError(
                ReadOnlySessionErrorCode.TRANSPORT_FAILED,
                "synthetic read-only transport failure",
            ),
        }
    )
    snapshot = collect_cbs250_inventory(executor, source_revision="unit-test")

    assert snapshot.fingerprint is not None
    assert snapshot.current_network_state is not None
    assert snapshot.current_network_state.basis.value == "observed_partial"
    assert snapshot.current_network_state.absence_is_authoritative is False
    assert snapshot.ssh is None
    assert snapshot.current_network_state.management.services == ()
    assert any(error.code == "transport_failed" for error in snapshot.errors)
    assert "show ip ssh" not in snapshot.commands_succeeded


def test_credentials_repr_is_redacted_and_forbidden_command_is_blocked_before_transport():
    credentials = SessionCredentials(username="operator", password="super-secret-value")
    assert "operator" not in repr(credentials)
    assert "super-secret-value" not in repr(credentials)

    session = ParamikoCBS250ReadOnlySession("192.0.2.1", credentials)
    try:
        session.execute("clear logging")
    except SafetyViolation:
        pass
    else:
        raise AssertionError("Forbidden command reached the read-only session")
