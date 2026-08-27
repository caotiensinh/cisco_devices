from cbs250_safety import SafetyViolation
from cisco_assistant.read_only_collectors import (
    BASELINE_COLLECTOR_COMMANDS,
    COLLECTOR_COMMANDS,
    COLLECTOR_SCHEMA_VERSION,
    SHOW_VLAN_PROMOTED_FIRMWARE,
    SHOW_VLAN_PROMOTED_PRODUCT_ID,
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
  Version: 3.5.3.3
  Date: 23-Mar-2026
Inactive-image:
  Version: 3.5.3.3
example-switch#
"""

SHOW_VERSION_OLD = """
show version
Active-image:
  Version: 3.3.0.16
  Date: 23-Mar-2023
example-switch#
"""

SHOW_IP_SSH = """
show ip ssh
SSH Server: Enabled
Password Authentication: Enabled
Public Key Authentication: Disabled
example-switch#
"""

SHOW_VLAN = "\n".join(
    [
        "show vlan",
        "Created by: S-Static, G-GVRP, R-Radius Assigned VLAN, V-Voice VLAN",
        f"{'VLAN':<8}{'Name':<18}{'Tagged Ports':<24}{'UnTagged Ports':<24}{'Created by'}",
        f"{'-----':<8}{'-----------':<18}{'--------------':<24}{'--------------':<24}{'----------'}",
        f"{1:<8}{'Default':<18}{'':<24}{'gi1/0/1':<24}{'S'}",
        f"{120:<8}{'CAMERAS':<18}{'gi1/0/2-4':<24}{'':<24}{'S'}",
        "example-switch#",
    ]
)


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


def full_outputs():
    return {
        "show system": SHOW_SYSTEM,
        "show version": SHOW_VERSION,
        "show ip ssh": SHOW_IP_SSH,
        "show vlan": SHOW_VLAN,
    }


def test_parsers_extract_exact_identity_and_ssh_state():
    system = parse_show_system(SHOW_SYSTEM)
    version = parse_show_version(SHOW_VERSION)
    ssh = parse_show_ip_ssh(SHOW_IP_SSH)

    assert system["product_id"] == SHOW_VLAN_PROMOTED_PRODUCT_ID
    assert system["system_description"].startswith("CBS250-24T-4X")
    assert system["temperature_celsius"] == 52
    assert system["temperature_status"] == "OK"
    assert version["firmware_version"] == SHOW_VLAN_PROMOTED_FIRMWARE
    assert ssh.server_enabled is True
    assert ssh.password_authentication_enabled is True
    assert ssh.public_key_authentication_enabled is False


def test_collector_runs_promoted_vlan_only_after_exact_identity_and_returns_partial_state():
    executor = FakeExecutor(full_outputs())
    snapshot = collect_cbs250_inventory(
        executor,
        source_revision="unit-test",
        collected_at_utc="2026-08-27T01:34:31+00:00",
    )

    assert COLLECTOR_SCHEMA_VERSION == 2
    assert tuple(executor.calls) == COLLECTOR_COMMANDS
    assert snapshot.fingerprint is not None
    assert snapshot.fingerprint.product_id == SHOW_VLAN_PROMOTED_PRODUCT_ID
    assert snapshot.fingerprint.firmware_version == SHOW_VLAN_PROMOTED_FIRMWARE
    assert snapshot.observed_state is not None
    assert snapshot.observed_state.vlan_ids == (1, 120)
    assert snapshot.observed_state.partial is True
    assert any(
        capability.feature_id == "vlan_8021q"
        and capability.source == "live:show vlan"
        for capability in snapshot.observed_state.capabilities
    )
    assert snapshot.current_network_state is not None
    assert [vlan.vlan_id for vlan in snapshot.current_network_state.vlans] == [1, 120]
    assert [vlan.name for vlan in snapshot.current_network_state.vlans] == ["Default", "CAMERAS"]
    assert snapshot.current_network_state.basis.value == "observed_partial"
    assert snapshot.current_network_state.absence_is_authoritative is False
    assert snapshot.current_network_state.management.services == ("ssh",)
    assert snapshot.complete_for_planner_scope is False
    assert snapshot.device_write_authority is False
    assert snapshot.errors == ()


def test_safe_export_includes_vlan_ids_but_not_names_ports_or_raw_outputs():
    executor = FakeExecutor(full_outputs())
    snapshot = collect_cbs250_inventory(executor, source_revision="unit-test")
    payload = snapshot.as_safe_dict()
    rendered = repr(payload)

    assert payload["credentials_exported"] is False
    assert payload["raw_command_output_exported"] is False
    assert payload["vlan_names_exported"] is False
    assert payload["port_membership_exported"] is False
    assert payload["current_network_state"]["vlans"] == [{"vlan_id": 1}, {"vlan_id": 120}]
    assert "00:11:22:33:44:55" not in rendered
    assert "example-switch" not in rendered
    assert "CAMERAS" not in rendered
    assert "gi1/0/" not in rendered
    assert "super-secret-value" not in rendered


def test_missing_identity_withholds_promoted_vlan_command_and_planner_state():
    executor = FakeExecutor(
        {
            "show system": "System Description: unknown\n",
            "show version": SHOW_VERSION,
            "show ip ssh": SHOW_IP_SSH,
        }
    )
    snapshot = collect_cbs250_inventory(executor, source_revision="unit-test")

    assert tuple(executor.calls) == BASELINE_COLLECTOR_COMMANDS
    assert "show vlan" not in executor.calls
    assert snapshot.fingerprint is None
    assert snapshot.observed_state is None
    assert snapshot.current_network_state is None
    assert any(error.code == "identity_incomplete" for error in snapshot.errors)


def test_wrong_firmware_blocks_show_vlan_before_transport_execution():
    executor = FakeExecutor(
        {
            "show system": SHOW_SYSTEM,
            "show version": SHOW_VERSION_OLD,
            "show ip ssh": SHOW_IP_SSH,
        }
    )
    snapshot = collect_cbs250_inventory(executor, source_revision="unit-test")

    assert tuple(executor.calls) == BASELINE_COLLECTOR_COMMANDS
    assert "show vlan" not in executor.calls
    assert snapshot.fingerprint is not None
    assert snapshot.fingerprint.firmware_version == "3.3.0.16"
    assert snapshot.observed_state is not None
    assert snapshot.observed_state.vlan_ids == ()
    assert snapshot.current_network_state is not None
    assert snapshot.current_network_state.vlans == ()
    assert snapshot.current_network_state.absence_is_authoritative is False
    assert any(error.code == "exact_target_mismatch_blocked" for error in snapshot.errors)


def test_partial_baseline_command_failure_is_explicit_and_vlan_collection_can_still_be_exact_gated():
    outputs = full_outputs()
    outputs["show ip ssh"] = ReadOnlySessionError(
        ReadOnlySessionErrorCode.TRANSPORT_FAILED,
        "synthetic read-only transport failure",
    )
    executor = FakeExecutor(outputs)
    snapshot = collect_cbs250_inventory(executor, source_revision="unit-test")

    assert snapshot.fingerprint is not None
    assert snapshot.current_network_state is not None
    assert [vlan.vlan_id for vlan in snapshot.current_network_state.vlans] == [1, 120]
    assert snapshot.current_network_state.basis.value == "observed_partial"
    assert snapshot.current_network_state.absence_is_authoritative is False
    assert snapshot.ssh is None
    assert snapshot.current_network_state.management.services == ()
    assert any(error.code == "transport_failed" for error in snapshot.errors)
    assert "show ip ssh" not in snapshot.commands_succeeded
    assert "show vlan" in snapshot.commands_succeeded


def test_vlan_parser_failure_is_explicit_and_never_makes_absence_authoritative():
    outputs = full_outputs()
    outputs["show vlan"] = "unexpected vlan output\n"
    executor = FakeExecutor(outputs)
    snapshot = collect_cbs250_inventory(executor, source_revision="unit-test")

    assert "show vlan" in snapshot.commands_succeeded
    assert snapshot.observed_state is not None
    assert snapshot.observed_state.vlan_ids == ()
    assert snapshot.current_network_state is not None
    assert snapshot.current_network_state.vlans == ()
    assert snapshot.current_network_state.absence_is_authoritative is False
    assert any(error.code == "collector_parse_error" for error in snapshot.errors)


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
