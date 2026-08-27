"""CBS250 parser foundation derived from documented display-field structures.

IMPORTANT: these parsers are DOCUMENTED_FORMAT_ONLY. They are not evidence that the exact
CBS250-24T-4X / 3.5.3.3 live output has been validated, and they are intentionally not wired
into the automated collector. Promotion requires exact live evidence and regression tests.

No network/device access and no command execution exists in this module.
"""
from __future__ import annotations

from dataclasses import dataclass
import re


PARSER_AUTHORITY = "DOCUMENTED_FORMAT_ONLY"
LIVE_VALIDATED = False

VLAN_FORMAT_LEGACY = "LEGACY_PORTS_TYPE_AUTHORIZATION"
VLAN_FORMAT_TAGGED_UNTAGGED = "TAGGED_UNTAGGED_CREATED_BY"


class DocumentedParserError(ValueError):
    """Raised when text does not satisfy the documented-format parser contract."""


@dataclass(frozen=True, slots=True)
class DocumentedVLANRow:
    vlan_id: int
    name: str
    ports: tuple[str, ...]
    vlan_type: str
    authorization: str
    format_variant: str = VLAN_FORMAT_LEGACY
    tagged_ports: tuple[str, ...] = ()
    untagged_ports: tuple[str, ...] = ()
    created_by: str | None = None


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


def _parse_port_cell(value: str) -> tuple[str, ...]:
    stripped = value.strip()
    if not stripped or stripped.casefold() in {"none", "--", "-"}:
        return ()
    return tuple(
        part.strip()
        for part in stripped.split(",")
        if part.strip() and part.strip().casefold() != "none"
    )


def _ordered_unique(*groups: tuple[str, ...]) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for group in groups:
        for item in group:
            if item not in seen:
                seen.add(item)
                result.append(item)
    return tuple(result)


def _find_current_vlan_header(line: str) -> tuple[int, int, int, int, int] | None:
    """Return fixed column starts for the current Cisco VLAN table shape."""
    lowered = line.casefold()
    labels = ("vlan", "name", "tagged ports", "untagged ports", "created by")
    starts: list[int] = []
    search_from = 0
    for label in labels:
        index = lowered.find(label, search_from)
        if index < 0:
            return None
        starts.append(index)
        search_from = index + len(label)
    return tuple(starts)  # type: ignore[return-value]


def _parse_current_vlan_rows(
    lines: list[str],
    header_index: int,
    starts: tuple[int, int, int, int, int],
) -> tuple[DocumentedVLANRow, ...]:
    vlan_start, name_start, tagged_start, untagged_start, created_start = starts
    rows: list[DocumentedVLANRow] = []

    for line in lines[header_index + 1 :]:
        stripped = line.strip()
        if not stripped or set(stripped) <= {"-", " ", "|"}:
            continue
        if _is_prompt_or_command_echo(line):
            continue

        vlan_cell = line[vlan_start:name_start].strip()
        if not re.fullmatch(r"\d{1,4}", vlan_cell):
            # Wrapped port-list continuation lines intentionally do not become new rows.
            continue

        vlan_id = int(vlan_cell)
        if not 1 <= vlan_id <= 4094:
            raise DocumentedParserError(f"Parsed VLAN ID outside valid range: {vlan_id}")

        name = line[name_start:tagged_start].strip()
        tagged = _parse_port_cell(line[tagged_start:untagged_start])
        untagged = _parse_port_cell(line[untagged_start:created_start])
        created_by = line[created_start:].strip()
        if not name:
            raise DocumentedParserError(f"Current-format VLAN {vlan_id} has an empty name")
        if not created_by:
            raise DocumentedParserError(f"Current-format VLAN {vlan_id} has no Created by value")

        rows.append(
            DocumentedVLANRow(
                vlan_id=vlan_id,
                name=name,
                ports=_ordered_unique(tagged, untagged),
                vlan_type="",
                authorization="",
                format_variant=VLAN_FORMAT_TAGGED_UNTAGGED,
                tagged_ports=tagged,
                untagged_ports=untagged,
                created_by=created_by,
            )
        )

    if not rows:
        raise DocumentedParserError(
            "show vlan current documented header was found but no current-format rows parsed"
        )
    return tuple(rows)


def _parse_legacy_vlan_rows(lines: list[str], header_index: int) -> tuple[DocumentedVLANRow, ...]:
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
        ports = _parse_port_cell(match.group("ports"))
        rows.append(
            DocumentedVLANRow(
                vlan_id=vlan_id,
                name=match.group("name"),
                ports=ports,
                vlan_type=match.group("type"),
                authorization=match.group("authorization").strip(),
                format_variant=VLAN_FORMAT_LEGACY,
            )
        )
    if not rows:
        raise DocumentedParserError(
            "show vlan legacy documented header was found but no legacy-format rows parsed"
        )
    return tuple(rows)


def parse_documented_show_vlan(text: str) -> tuple[DocumentedVLANRow, ...]:
    """Parse either Cisco-documented ``show vlan`` table shape.

    Supported documented variants are:
    - legacy: VLAN / Name / Ports / Type / Authorization
    - current: VLAN / Name / Tagged Ports / UnTagged Ports / Created by

    Header recognition is mandatory. For the current format, fixed column starts are derived
    from the header so empty Tagged/UnTagged cells are preserved instead of being shifted by
    whitespace splitting. Missing rows never imply device absence.
    """
    lines = _clean_lines(text)

    for index, line in enumerate(lines):
        starts = _find_current_vlan_header(line)
        if starts is not None:
            return _parse_current_vlan_rows(lines, index, starts)

    for index, line in enumerate(lines):
        lowered = line.casefold()
        if all(word in lowered for word in ("vlan", "name", "ports", "type", "authorization")):
            return _parse_legacy_vlan_rows(lines, index)

    raise DocumentedParserError("show vlan documented header was not found")


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
