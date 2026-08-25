"""Presentation-safe normalized current-state preview for offline dry runs."""
from __future__ import annotations

from dataclasses import dataclass

from .current_state import CurrentNetworkState


@dataclass(frozen=True, slots=True)
class CurrentStatePreview:
    basis: str
    collected_at_utc: str | None
    source_revision: str | None
    vlans: tuple[dict[str, object], ...]
    access_ports: tuple[dict[str, object], ...]
    trunks: tuple[dict[str, object], ...]
    management: dict[str, object] | None
    satisfied_security_rules: tuple[str, ...]
    absence_is_authoritative: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "basis": self.basis,
            "collected_at_utc": self.collected_at_utc,
            "source_revision": self.source_revision,
            "absence_is_authoritative": self.absence_is_authoritative,
            "vlans": list(self.vlans),
            "access_ports": list(self.access_ports),
            "trunks": list(self.trunks),
            "management": self.management,
            "satisfied_security_rules": list(self.satisfied_security_rules),
        }

    def render_text(self) -> str:
        lines = [
            "CURRENT NETWORK STATE",
            "=====================",
            f"Basis: {self.basis}",
            f"Absence authoritative: {'YES' if self.absence_is_authoritative else 'NO'}",
            f"Collected at: {self.collected_at_utc or 'not-applicable'}",
            f"Source revision: {self.source_revision or 'not-applicable'}",
            "",
            "CURRENT VLANS",
            "-------------",
        ]
        if self.vlans:
            for vlan in self.vlans:
                lines.append(
                    f"VLAN {vlan['vlan_id']} {vlan['name']} "
                    f"network={vlan['network'] or '-'} gateway={vlan['gateway'] or '-'}"
                )
        else:
            lines.append("None in normalized current scope.")

        lines.extend(["", "CURRENT ACCESS PORTS", "--------------------"])
        if self.access_ports:
            for port in self.access_ports:
                lines.append(f"{port['interface']}: access_vlan={port['access_vlan']}")
        else:
            lines.append("None in normalized current scope.")

        lines.extend(["", "CURRENT TRUNKS", "--------------"])
        if self.trunks:
            for trunk in self.trunks:
                allowed = ",".join(str(vlan) for vlan in trunk["allowed_vlans"])
                lines.append(
                    f"{trunk['interface']}: allowed=[{allowed}] native={trunk['native_vlan'] or 'not-set'}"
                )
        else:
            lines.append("None in normalized current scope.")

        lines.extend(["", "CURRENT MANAGEMENT", "------------------"])
        if self.management is None:
            lines.append("Not present in normalized current scope.")
        else:
            lines.append(f"VLAN: {self.management['vlan_id'] or 'not-set'}")
            lines.append(
                "Sources: "
                + (", ".join(self.management["allowed_source_networks"]) or "not-declared")
            )
            lines.append(
                "Services: " + (", ".join(self.management["services"]) or "not-declared")
            )

        lines.extend(["", "CURRENT SECURITY COMPLIANCE", "---------------------------"])
        if self.satisfied_security_rules:
            lines.extend(f"- {rule}" for rule in self.satisfied_security_rules)
        else:
            lines.append("No satisfied security rules recorded in normalized current scope.")
        return "\n".join(lines)


def build_current_state_preview(state: CurrentNetworkState) -> CurrentStatePreview:
    management = None
    if state.management is not None:
        management = {
            "vlan_id": state.management.vlan_id,
            "allowed_source_networks": list(state.management.allowed_source_networks),
            "services": list(state.management.services),
        }

    return CurrentStatePreview(
        basis=state.basis.value,
        collected_at_utc=state.collected_at_utc,
        source_revision=state.source_revision,
        vlans=tuple(
            {
                "vlan_id": vlan.vlan_id,
                "name": vlan.name,
                "network": vlan.network,
                "gateway": vlan.gateway,
            }
            for vlan in sorted(state.vlans, key=lambda item: item.vlan_id)
        ),
        access_ports=tuple(
            {"interface": port.interface, "access_vlan": port.access_vlan}
            for port in sorted(state.access_ports, key=lambda item: item.interface.casefold())
        ),
        trunks=tuple(
            {
                "interface": trunk.interface,
                "allowed_vlans": list(trunk.allowed_vlans),
                "native_vlan": trunk.native_vlan,
            }
            for trunk in sorted(state.trunks, key=lambda item: item.interface.casefold())
        ),
        management=management,
        satisfied_security_rules=state.satisfied_security_rules,
        absence_is_authoritative=state.absence_is_authoritative,
    )
