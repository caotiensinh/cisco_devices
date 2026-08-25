"""CBS250 parser foundation derived from documented display-field structures.

IMPORTANT: these parsers are DOCUMENTED_FORMAT_ONLY. They are not evidence that the exact
CBS250-24T-4X / 3.5.3.3 live output has been validated, and they are intentionally not wired
into the automated collector. Promotion requires exact live fixtures and regression tests.

No network/device access and no command execution exists in this module.
"""
from __future__ import annotations

from dataclasses import dataclass
import re


PARSER_AUTHORITY = "DOCUMENTED_FORMAT_ONLY"
LIVE_VALIDATED = False


class DocumentedParserError(ValueError):
    """Raised when text does not satisfy the documented-format parser contract."""


@dataclass(frozen=True, slots=True)
class DocumentedVLANRow:
    vlan_id: int
    name: str
    ports: tuple[str, ...]
    vlan_type: str
    authorization: str


@dataclass(frozen=True, slots=True)
class DocumentedInterfaceStatusRow:
    interface: str
    media_type: str
    duplex: str
    speed: str
    negotiation: str
    flow_control: str
    link_state: str
    back_pressure: str
    mdix_mode: str


@dataclass(frozen=True, slots=True)
class DocumentedSwitchportState:
    name: str
    switchport: str | None
    administrative_mode: str | None
    operational_mode: str | None
    access_mode_vlan: str | None
    trunking_native_mode_vlan: str | None
    general_pvid: str | None
    fields: tuple[tuple[str, str], ...]

    @property
    def field_map(self) -> dict[str, str]:
        return dict(self.fields)


def _clean_lines(text: str) -> list[str]:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return [line.rstrip() for line in normalized.splitlines()]


def _is_prompt_or_command_echo(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    if re.match(r"^\S+[>#]", stripped):
        return True
    if stripped.lower().startswith("gathering information"):
        return True
    return False


def parse_documented_show_vlan(text: str) -> tuple[DocumentedVLANRow, ...]:
    """Parse the documented five-column ``show vlan`` table shape.

    The parser intentionally requires the recognizable VLAN/Name/Ports/Type/Authorization
    header before accepting rows. It does not claim that missing rows represent device absence.
    """
    lines = _clean_lines(text)
    header_index = None
    for index, line in enumerate(lines):
        lowered = line.casefold()
        if all(word in lowered for word in ("vlan", "name", "ports", "type", "authorization")):
            header_index = index
            break
    if header_index is None:
        raise DocumentedParserError("show vlan documented header was not found")

    rows: list[DocumentedVLANRow] = []
    row_re = re.compile(
        r"^\s*(?P<vlan>\d{1,4})\s+"
        r"(?P<name>\S+)\s+"
        r"(?P<ports>\S+)\s+"
        r"(?P<type>\S+)\s+"
        r"(?P<authorization>.+?)\s*$"
    )
    for line in lines[header_index + 1 :]:
        stripped = line.strip()
        if not stripped or set(stripped) <= {"-", " ", "|"}:
            continue
        if _is_prompt_or_command_echo(line):
            continue
        match = row_re.match(line)
        if not match:
            continue
        vlan_id = int(match.group("vlan"))
        if not 1 <= vlan_id <= 4094:
            raise DocumentedParserError(f"Parsed VLAN ID outside valid range: {vlan_id}")
        ports_text = match.group("ports")
        ports = tuple(part for part in ports_text.split(",") if part and part.casefold() != "none")
        rows.append(
            DocumentedVLANRow(
                vlan_id=vlan_id,
                name=match.group("name"),
                ports=ports,
                vlan_type=match.group("type"),
                authorization=match.group("authorization").strip(),
            )
        )
    if not rows:
        raise DocumentedParserError("show vlan header was found but no documented-format rows parsed")
    return tuple(rows)


def parse_documented_show_interfaces_status(
    text: str,
) -> tuple[DocumentedInterfaceStatusRow, ...]:
    """Parse documented physical-interface rows from ``show interfaces status``.

    Port-channel summary rows are deliberately not normalized by this foundation parser because
    their documented table has a different shape. They remain pending a dedicated exact-live
    parser contract.
    """
    lines = _clean_lines(text)
    header_seen = any(
        all(word in line.casefold() for word in ("port", "type", "duplex", "speed"))
        for line in lines
    )
    if not header_seen:
        raise DocumentedParserError("show interfaces status documented header was not found")

    rows: list[DocumentedInterfaceStatusRow] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or _is_prompt_or_command_echo(line):
            continue
        parts = stripped.split()
        if len(parts) != 9:
            continue
        interface = parts[0]
        if not re.match(r"^(?:gi|ge|te|xg|GigabitEthernet|TenGigabitEthernet)\S*$", interface, re.I):
            continue
        rows.append(
            DocumentedInterfaceStatusRow(
                interface=interface,
                media_type=parts[1],
                duplex=parts[2],
                speed=parts[3],
                negotiation=parts[4],
                flow_control=parts[5],
                link_state=parts[6],
                back_pressure=parts[7],
                mdix_mode=parts[8],
            )
        )
    if not rows:
        raise DocumentedParserError(
            "show interfaces status header was found but no documented physical-interface rows parsed"
        )
    return tuple(rows)


def parse_documented_show_interfaces_switchport(text: str) -> DocumentedSwitchportState:
    """Parse documented key/value fields from one switchport detail block.

    Unknown key/value fields are retained instead of discarded. This prevents the documented
    foundation from pretending it knows the complete exact-live 3.5.3.3 field set.
    """
    fields: list[tuple[str, str]] = []
    for line in _clean_lines(text):
        if _is_prompt_or_command_echo(line):
            continue
        match = re.match(r"^\s*([^:]+?)\s*:\s*(.*?)\s*$", line)
        if not match:
            continue
        key = " ".join(match.group(1).split())
        value = match.group(2).strip()
        if key and value:
            fields.append((key, value))

    field_map = dict(fields)
    name = field_map.get("Name")
    if not name:
        raise DocumentedParserError("show interfaces switchport Name field was not found")

    return DocumentedSwitchportState(
        name=name,
        switchport=field_map.get("Switchport"),
        administrative_mode=field_map.get("Administrative Mode"),
        operational_mode=field_map.get("Operational Mode"),
        access_mode_vlan=field_map.get("Access Mode VLAN"),
        trunking_native_mode_vlan=field_map.get("Trunking Native Mode VLAN"),
        general_pvid=field_map.get("General PVID"),
        fields=tuple(fields),
    )
