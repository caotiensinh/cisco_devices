"""End-to-end offline design workflow bound to a typed device capability profile.

This module intentionally stops before any provider/compiler or device execution layer.
It combines a versioned template, normalized intent, exact-device profile validation, and
human-readable preview data. No Cisco CLI is generated.
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import ObservedState
from .preview import DesignPreview, build_design_preview
from .profiles import DeviceProfile, validate_intent_against_profile
from .templates import TemplateBuildResult, TemplateRequest, build_template
from .validation import ValidationIssue, ValidationResult


@dataclass(frozen=True, slots=True)
class TargetDevicePreview:
    profile_id: str
    product_id: str
    firmware_version: str
    binding_status: str
    authority_note: str

    def as_dict(self) -> dict[str, str]:
        return {
            "profile_id": self.profile_id,
            "product_id": self.product_id,
            "firmware_version": self.firmware_version,
            "binding_status": self.binding_status,
            "authority_note": self.authority_note,
        }


@dataclass(frozen=True, slots=True)
class DeviceAwareDesignPreview:
    """Presentation-ready output for one offline, exact-device-aware design pass."""

    target: TargetDevicePreview
    template_result: TemplateBuildResult
    design: DesignPreview
    profile_validation: ValidationResult
    require_live_proof: bool
    device_commands_generated: bool = False

    @property
    def overall_valid(self) -> bool:
        return self.design.validation_valid and self.profile_validation.valid

    @property
    def blocking_issues(self) -> tuple[ValidationIssue, ...]:
        return self.profile_validation.blocking

    def as_dict(self) -> dict[str, object]:
        result = self.design.as_dict()
        result["target_device"] = self.target.as_dict()
        result["capability_validation"] = {
            "mode": "live_proof_required" if self.require_live_proof else "offline_design",
            "valid": self.profile_validation.valid,
            "issues": [
                {
                    "code": issue.code,
                    "severity": issue.severity.value,
                    "message": issue.message,
                    "remediation": issue.remediation,
                }
                for issue in self.profile_validation.issues
            ],
        }
        result["overall_valid"] = self.overall_valid
        result["device_commands_generated"] = False
        return result

    def render_text(self) -> str:
        lines = [
            "TARGET DEVICE",
            "=============",
            f"Profile: {self.target.profile_id}",
            f"Product: {self.target.product_id}",
            f"Firmware: {self.target.firmware_version}",
            f"Binding: {self.target.binding_status}",
            "Device commands generated: NO",
            "",
            self.design.render_text(),
            "",
            "CAPABILITY / RESOURCE VALIDATION",
            "================================",
            (
                "Mode: LIVE PROOF REQUIRED"
                if self.require_live_proof
                else "Mode: OFFLINE DESIGN"
            ),
            f"Status: {'PASS' if self.profile_validation.valid else 'BLOCKED'}",
        ]

        if self.profile_validation.issues:
            for issue in self.profile_validation.issues:
                lines.append(f"[{issue.severity.value}] {issue.code}: {issue.message}")
                if issue.remediation:
                    lines.append(f"  Remediation: {issue.remediation}")
        else:
            lines.append("No capability/resource validation issues.")

        lines.extend(
            [
                "",
                "OVERALL RESULT",
                "==============",
                f"Status: {'PASS' if self.overall_valid else 'BLOCKED'}",
                "No device configuration was generated or executed.",
            ]
        )
        return "\n".join(lines)


def build_device_aware_design_preview(
    request: TemplateRequest,
    profile: DeviceProfile,
    *,
    observed_state: ObservedState | None = None,
    require_live_proof: bool = False,
) -> DeviceAwareDesignPreview:
    """Run the complete offline design path for one target device profile.

    Flow:

    TemplateRequest -> normalized NetworkIntent -> generic validation -> exact device/profile
    validation -> presentation preview.

    `require_live_proof=False` is the normal offline design mode. Family-documented but
    unobserved features remain visible as warnings. `require_live_proof=True` models the
    stricter future provider precheck and fails closed until required capabilities are proven
    `documented_and_observed`.
    """
    template_result = build_template(request)
    profile_validation = validate_intent_against_profile(
        template_result.intent,
        profile,
        observed_state=observed_state,
        require_live_proof=require_live_proof,
    )
    design = build_design_preview(template_result)

    target = TargetDevicePreview(
        profile_id=profile.profile_id,
        product_id=profile.fingerprint.product_id,
        firmware_version=profile.fingerprint.firmware_version,
        binding_status=profile.binding_status,
        authority_note=profile.authority_note,
    )

    return DeviceAwareDesignPreview(
        target=target,
        template_result=template_result,
        design=design,
        profile_validation=profile_validation,
        require_live_proof=require_live_proof,
    )
