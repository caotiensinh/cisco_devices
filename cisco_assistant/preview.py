"""Deterministic, human-readable design preview for normalized network intent.

The preview is presentation data only. It does not emit Cisco CLI and has no device access.
"""
from __future__ import annotations

from dataclasses import dataclass

from .templates import TemplateBuildResult


@dataclass(frozen=True, slots=True)
class VLANPreviewRow:
    vlan_id: int
    name: str
    purpose: str
    network: str | None
    gateway: str | None


@dataclass(frozen=True, slots=True)
class PortPreviewRow:
    interface: str
    role: str
    mode: str
    vlan: int | None


@dataclass(frozen=True, slots=True)
class UplinkPreviewRow:
    interface: str
    allowed_vlans: tuple[int, ...]
    native_vlan: int | None


@dataclass(frozen=True, slots=True)
class PreviewIssue:
    code: str
    severity: str
    message: str
    remediation: str | None


@dataclass(frozen=True, slots=True)
class DesignPreview:
    template_id: str
    template_version: str
    template_name: str
    site_name: str
    security_profile: str
    inter_vlan_routing: bool
    management_vlan: int | None
    management_source_networks: tuple[str, ...]
    vlans: tuple[VLANPreviewRow, ...]
    ports: tuple[PortPreviewRow, ...]
    uplinks: tuple[UplinkPreviewRow, ...]
    unassigned_interfaces: tuple[str, ...]
    validation_valid: bool
    validation_issues: tuple[PreviewIssue, ...]
    notes: tuple[str, ...]
    device_commands_generated: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "template": {
                "id": self.template_id,
                "version": self.template_version,
                "name": self.template_name,
            },
            "site_name": self.site_name,
            "security_profile": self.security_profile,
            "inter_vlan_routing": self.inter_vlan_routing,
            "management": {
                "vlan": self.management_vlan,
                "allowed_source_networks": list(self.management_source_networks),
            },
            "vlans": [
                {
                    "id": row.vlan_id,
                    "name": row.name,
                    "purpose": row.purpose,
                    "network": row.network,
                    "gateway": row.gateway,
                }
                for row in self.vlans
            ],
            "ports": [
                {
                    "interface": row.interface,
                    "role": row.role,
                    "mode": row.mode,
                    "vlan": row.vlan,
                }
                for row in self.ports
            ],
            "uplinks": [
                {
                    "interface": row.interface,
                    "allowed_vlans": list(row.allowed_vlans),
                    "native_vlan": row.native_vlan,
                }
                for row in self.uplinks
            ],
            "unassigned_interfaces": list(self.unassigned_interfaces),
            "validation": {
                "valid": self.validation_valid,
                "issues": [
                    {
                        "code": issue.code,
                        "severity": issue.severity,
                        "message": issue.message,
                        "remediation": issue.remediation,
                    }
                    for issue in self.validation_issues
                ],
            },
            "notes": list(self.notes),
            "device_commands_generated": self.device_commands_generated,
        }

    def render_text(self) -> str:
        lines: list[str] = [
            "NETWORK DESIGN PREVIEW",
            "======================",
            f"Site: {self.site_name}",
            f"Template: {self.template_name} ({self.template_id}@{self.template_version})",
            f"Security profile: {self.security_profile}",
            f"Inter-VLAN routing requested: {'YES' if self.inter_vlan_routing else 'NO'}",
            "Device commands generated: NO",
            "",
            "VLAN / IP PLAN",
            "--------------",
        ]

        for row in self.vlans:
            lines.append(
                f"VLAN {row.vlan_id:<4} {row.name:<12} "
                f"network={row.network or '-':<18} gateway={row.gateway or '-'} "
                f"purpose={row.purpose}"
            )

        lines.extend(["", "ACCESS PORT PLAN", "----------------"])
        if self.ports:
            for row in self.ports:
                lines.append(
                    f"{row.interface}: role={row.role} mode={row.mode} vlan={row.vlan}"
                )
        else:
            lines.append("No access ports assigned yet.")

        lines.extend(["", "UPLINK PLAN", "-----------"])
        if self.uplinks:
            for row in self.uplinks:
                allowed = ",".join(str(value) for value in row.allowed_vlans)
                native = str(row.native_vlan) if row.native_vlan is not None else "not-set"
                lines.append(
                    f"{row.interface}: allowed_vlans=[{allowed}] native_vlan={native}"
                )
        else:
            lines.append("No uplink declared yet.")

        lines.extend(["", "MANAGEMENT", "----------"])
        lines.append(
            f"Management VLAN: {self.management_vlan if self.management_vlan is not None else 'not-set'}"
        )
        lines.append(
            "Allowed sources: "
            + (", ".join(self.management_source_networks) if self.management_source_networks else "not-declared")
        )

        lines.extend(["", "VALIDATION", "----------"])
        lines.append(f"Status: {'PASS' if self.validation_valid else 'BLOCKED'}")
        if self.validation_issues:
            for issue in self.validation_issues:
                lines.append(f"[{issue.severity}] {issue.code}: {issue.message}")
                if issue.remediation:
                    lines.append(f"  Remediation: {issue.remediation}")
        else:
            lines.append("No validation issues.")

        if self.unassigned_interfaces:
            lines.extend(["", "UNASSIGNED INTERFACES", "---------------------"])
            lines.append(", ".join(self.unassigned_interfaces))

        if self.notes:
            lines.extend(["", "ASSUMPTIONS / NOTES", "-------------------"])
            for note in self.notes:
                lines.append(f"- {note}")

        return "\n".join(lines)


def build_design_preview(result: TemplateBuildResult) -> DesignPreview:
    intent = result.intent
    management = intent.management

    return DesignPreview(
        template_id=result.definition.template_id.value,
        template_version=result.definition.version,
        template_name=result.definition.display_name,
        site_name=intent.site_name,
        security_profile=intent.security_profile.value,
        inter_vlan_routing=intent.routing.inter_vlan_routing,
        management_vlan=management.vlan_id if management is not None else None,
        management_source_networks=(
            management.allowed_source_networks if management is not None else ()
        ),
        vlans=tuple(
            VLANPreviewRow(
                vlan_id=vlan.id,
                name=vlan.name,
                purpose=vlan.purpose,
                network=vlan.network,
                gateway=vlan.gateway,
            )
            for vlan in intent.vlans
        ),
        ports=tuple(
            PortPreviewRow(
                interface=port.interface,
                role=port.role,
                mode=port.mode.value,
                vlan=port.access_vlan,
            )
            for port in intent.ports
        ),
        uplinks=tuple(
            UplinkPreviewRow(
                interface=uplink.interface,
                allowed_vlans=uplink.allowed_vlans,
                native_vlan=uplink.native_vlan,
            )
            for uplink in intent.uplinks
        ),
        unassigned_interfaces=result.unassigned_interfaces,
        validation_valid=result.validation.valid,
        validation_issues=tuple(
            PreviewIssue(
                code=issue.code,
                severity=issue.severity.value,
                message=issue.message,
                remediation=issue.remediation,
            )
            for issue in result.validation.issues
        ),
        notes=result.notes,
    )
