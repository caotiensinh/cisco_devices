"""CBS250 read-only inventory collectors and parsers.

Collectors in this module can request only commands already approved by ``cbs250_safety``.
They normalize evidence into product models but deliberately return ``OBSERVED_PARTIAL`` until
VLAN/port/routing collectors are separately reviewed and added to the exact allowlist.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from typing import Protocol

from cbs250_safety import READ_ONLY_EXEC_ALLOWLIST

from .current_state import CurrentManagementState, CurrentNetworkState, CurrentStateBasis
from .models import (
    CapabilityState,
    DeviceCapability,
    DeviceFingerprint,
    ObservedState,
)
from .read_only_transport import ReadOnlyCommandResult, ReadOnlySessionError


COLLECTOR_SCHEMA_VERSION = 1
COLLECTOR_COMMANDS = (
    "show system",
    "show version",
    "show ip ssh",
)

if not set(COLLECTOR_COMMANDS).issubset(READ_ONLY_EXEC_ALLOWLIST):
    raise RuntimeError("Collector command registry exceeds the exact read-only allowlist")


class ReadOnlyCommandExecutor(Protocol):
    def execute(self, command: str) -> ReadOnlyCommandResult: ...


@dataclass(frozen=True, slots=True)
class CollectorError:
    command: str
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class SSHInventory:
    server_enabled: bool | None
    password_authentication_enabled: bool | None
    public_key_authentication_enabled: bool | None


@dataclass(frozen=True, slots=True)
class CBS250InventorySnapshot:
    schema_version: int
    collected_at_utc: str
    source_revision: str
    fingerprint: DeviceFingerprint | None
    observed_state: ObservedState | None
    current_network_state: CurrentNetworkState | None
    ssh: SSHInventory | None
    system_description: str | None = None
    temperature_celsius: int | None = None
    temperature_status: str | None = None
    commands_succeeded: tuple[str, ...] = field(default_factory=tuple)
    errors: tuple[CollectorError, ...] = field(default_factory=tuple)
    complete_for_planner_scope: bool = False
    device_write_authority: bool = False

    @property
    def partial(self) -> bool:
        return not self.complete_for_planner_scope

    def as_safe_dict(self) -> dict[str, object]:
        fingerprint = None
        if self.fingerprint is not None:
            fingerprint = {
                "vendor": self.fingerprint.vendor,
                "family": self.fingerprint.family,
                "product_id": self.fingerprint.product_id,
                "firmware_version": self.fingerprint.firmware_version,
                "management_protocol": self.fingerprint.management_protocol,
                "capability_dataset": self.fingerprint.capability_dataset,
            }

        current = None
        if self.current_network_state is not None:
            management = self.current_network_state.management
            current = {
                "basis": self.current_network_state.basis.value,
                "vlans": [],
                "access_ports": [],
                "trunks": [],
                "management": None
                if management is None
                else {
                    "vlan_id": management.vlan_id,
                    "allowed_source_networks": list(management.allowed_source_networks),
                    "services": list(management.services),
                },
                "satisfied_security_rules": list(
                    self.current_network_state.satisfied_security_rules
                ),
                "collected_at_utc": self.current_network_state.collected_at_utc,
                "source_revision": self.current_network_state.source_revision,
                "absence_is_authoritative": False,
            }

        return {
            "schema_version": self.schema_version,
            "collected_at_utc": self.collected_at_utc,
            "source_revision": self.source_revision,
            "fingerprint": fingerprint,
            "system_description": self.system_description,
            "temperature_celsius": self.temperature_celsius,
            "temperature_status": self.temperature_status,
            "ssh": None
            if self.ssh is None
            else {
                "server_enabled": self.ssh.server_enabled,
                "password_authentication_enabled": self.ssh.password_authentication_enabled,
                "public_key_authentication_enabled": self.ssh.public_key_authentication_enabled,
            },
            "current_network_state": current,
            "commands_succeeded": list(self.commands_succeeded),
            "errors": [
                {"command": error.command, "code": error.code, "message": error.message}
                for error in self.errors
            ],
            "complete_for_planner_scope": False,
            "partial": True,
            "device_write_authority": False,
            "credentials_exported": False,
            "raw_command_output_exported": False,
        }


def _value_after_label(text: str, label: str) -> str | None:
    pattern = re.compile(rf"^\s*{re.escape(label)}\s*:\s*(.*?)\s*$", re.IGNORECASE | re.MULTILINE)
    match = pattern.search(text)
    return match.group(1).strip() if match else None


def _parse_bool_label(text: str, labels: tuple[str, ...]) -> bool | None:
    for label in labels:
        value = _value_after_label(text, label)
        if value is None:
            continue
        normalized = value.strip().lower()
        if normalized in {"enabled", "enable", "yes", "true", "on"}:
            return True
        if normalized in {"disabled", "disable", "no", "false", "off"}:
            return False
    return None


def parse_show_system(text: str) -> dict[str, object]:
    description = _value_after_label(text, "System Description")
    model = None
    if description:
        match = re.search(r"\b(CBS\d{3,4}-[A-Za-z0-9-]+)\b", description)
        if match:
            model = match.group(1)

    if model is None:
        for label in ("System Type", "System Model", "Product ID", "PID"):
            value = _value_after_label(text, label)
            if value:
                match = re.search(r"\b(CBS\d{3,4}-[A-Za-z0-9-]+)\b", value)
                if match:
                    model = match.group(1)
                    break

    temperature = None
    status = None
    for label in ("Temperature", "System Temperature"):
        value = _value_after_label(text, label)
        if value:
            match = re.search(r"(-?\d+)\s*(?:C|Celsius)?\b", value, re.IGNORECASE)
            if match:
                temperature = int(match.group(1))
                break
    for label in ("Temperature Status", "System Temperature Status"):
        value = _value_after_label(text, label)
        if value:
            status = value
            break

    return {
        "system_description": description,
        "product_id": model,
        "temperature_celsius": temperature,
        "temperature_status": status,
    }


def parse_show_version(text: str) -> dict[str, object]:
    versions = re.findall(
        r"^\s*(?:Version|Image Version|Firmware Version)\s*:\s*([0-9]+(?:\.[0-9]+){2,})\s*$",
        text,
        flags=re.IGNORECASE | re.MULTILINE,
    )
    if not versions:
        versions = re.findall(r"\b(\d+\.\d+\.\d+\.\d+)\b", text)
    firmware = versions[0] if versions else None

    build_date = None
    for label in ("Date", "Build Date", "Image Date"):
        value = _value_after_label(text, label)
        if value and re.search(r"\d{1,2}-[A-Za-z]{3}-\d{4}", value):
            build_date = value
            break

    return {"firmware_version": firmware, "build_date": build_date}


def parse_show_ip_ssh(text: str) -> SSHInventory:
    server = _parse_bool_label(
        text,
        ("SSH Server", "SSH Server Status", "SSH server"),
    )
    if server is None:
        lowered = text.lower()
        if "ssh server enabled" in lowered:
            server = True
        elif "ssh server disabled" in lowered:
            server = False

    password = _parse_bool_label(
        text,
        ("Password Authentication", "Password authentication"),
    )
    public_key = _parse_bool_label(
        text,
        ("Public Key Authentication", "Public key authentication"),
    )
    return SSHInventory(
        server_enabled=server,
        password_authentication_enabled=password,
        public_key_authentication_enabled=public_key,
    )


def collect_cbs250_inventory(
    executor: ReadOnlyCommandExecutor,
    *,
    source_revision: str,
    collected_at_utc: str | None = None,
) -> CBS250InventorySnapshot:
    """Collect the currently reviewed R0 inventory subset.

    This function intentionally cannot claim planner-scope completeness because VLAN/port/L3
    collectors are not yet allowlisted. It returns ``OBSERVED_PARTIAL`` whenever device
    identity can be normalized.
    """
    timestamp = collected_at_utc or datetime.now(timezone.utc).isoformat()
    outputs: dict[str, str] = {}
    succeeded: list[str] = []
    errors: list[CollectorError] = []

    for command in COLLECTOR_COMMANDS:
        try:
            result = executor.execute(command)
            outputs[command] = result.output
            succeeded.append(command)
        except ReadOnlySessionError as exc:
            errors.append(
                CollectorError(
                    command=command,
                    code=exc.code.value,
                    message=str(exc),
                )
            )
        except Exception as exc:  # parser/orchestrator boundary: keep failure explicit
            errors.append(
                CollectorError(
                    command=command,
                    code="collector_execution_error",
                    message=f"Read-only collection failed: {type(exc).__name__}",
                )
            )

    system = parse_show_system(outputs.get("show system", ""))
    version = parse_show_version(outputs.get("show version", ""))
    ssh = parse_show_ip_ssh(outputs["show ip ssh"]) if "show ip ssh" in outputs else None

    product_id = system.get("product_id")
    firmware_version = version.get("firmware_version")
    fingerprint: DeviceFingerprint | None = None
    observed_state: ObservedState | None = None
    current_state: CurrentNetworkState | None = None

    if isinstance(product_id, str) and isinstance(firmware_version, str):
        fingerprint = DeviceFingerprint(
            vendor="Cisco",
            family="CBS250",
            product_id=product_id,
            firmware_version=firmware_version,
            management_protocol="ssh",
        )

        capabilities: list[DeviceCapability] = []
        management_services: list[str] = []
        if ssh is not None and ssh.server_enabled is True:
            capabilities.append(
                DeviceCapability(
                    feature_id="ssh_management",
                    state=CapabilityState.DOCUMENTED_AND_OBSERVED,
                    source="live:show ip ssh",
                    risk_class="R0",
                )
            )
            management_services.append("ssh")

        observed_state = ObservedState(
            fingerprint=fingerprint,
            collected_at_utc=timestamp,
            source_revision=source_revision,
            capabilities=tuple(capabilities),
            partial=True,
        )
        current_state = CurrentNetworkState(
            basis=CurrentStateBasis.OBSERVED_PARTIAL,
            management=CurrentManagementState(
                vlan_id=None,
                services=tuple(management_services),
            ),
            collected_at_utc=timestamp,
            source_revision=source_revision,
        )

    if fingerprint is None:
        errors.append(
            CollectorError(
                command="inventory_identity",
                code="identity_incomplete",
                message=(
                    "Exact product ID and firmware could not both be normalized; "
                    "planner current-state output is withheld."
                ),
            )
        )

    return CBS250InventorySnapshot(
        schema_version=COLLECTOR_SCHEMA_VERSION,
        collected_at_utc=timestamp,
        source_revision=source_revision,
        fingerprint=fingerprint,
        observed_state=observed_state,
        current_network_state=current_state,
        ssh=ssh,
        system_description=system.get("system_description")
        if isinstance(system.get("system_description"), str)
        else None,
        temperature_celsius=system.get("temperature_celsius")
        if isinstance(system.get("temperature_celsius"), int)
        else None,
        temperature_status=system.get("temperature_status")
        if isinstance(system.get("temperature_status"), str)
        else None,
        commands_succeeded=tuple(succeeded),
        errors=tuple(errors),
        complete_for_planner_scope=False,
    )
