"""End-to-end offline dry-run orchestration.

This joins exact-device-aware design validation with the semantic diff planner. It still stops
strictly before any provider compiler or executor and therefore cannot generate or run CLI.
"""
from __future__ import annotations

from dataclasses import dataclass

from .current_state import CurrentNetworkState
from .models import ObservedState
from .planner import ChangePlan, build_change_plan
from .profiles import DeviceProfile
from .templates import TemplateRequest
from .workflow import DeviceAwareDesignPreview, build_device_aware_design_preview


@dataclass(frozen=True, slots=True)
class DeviceAwareDryRun:
    design: DeviceAwareDesignPreview
    plan: ChangePlan
    device_commands_generated: bool = False
    execution_authority: bool = False

    @property
    def design_valid(self) -> bool:
        return self.design.overall_valid

    @property
    def provider_ready(self) -> bool:
        return self.design_valid and self.plan.provider_ready

    @property
    def status(self) -> str:
        if not self.design_valid:
            return "DESIGN_BLOCKED"
        if not self.plan.changes_required:
            return "NO_CHANGES"
        if self.provider_ready:
            return "PROVIDER_READY_DRY_RUN_ONLY"
        return "DRY_RUN_BLOCKED_FOR_PROVIDER"

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "design_valid": self.design_valid,
            "provider_ready": self.provider_ready,
            "execution_authority": False,
            "device_commands_generated": False,
            "design": self.design.as_dict(),
            "change_plan": self.plan.as_dict(),
        }

    def render_text(self) -> str:
        return "\n".join(
            [
                "OFFLINE DEVICE-AWARE DRY RUN",
                "============================",
                f"Status: {self.status}",
                "Execution authority: FALSE",
                "Device commands generated: NO",
                "",
                self.design.render_text(),
                "",
                self.plan.render_text(),
                "",
                "DRY RUN RESULT",
                "==============",
                f"Design valid: {'YES' if self.design_valid else 'NO'}",
                f"Provider ready: {'YES' if self.provider_ready else 'NO'}",
                "Execution allowed: NO",
            ]
        )


def build_device_aware_dry_run(
    request: TemplateRequest,
    profile: DeviceProfile,
    current_state: CurrentNetworkState,
    *,
    observed_state: ObservedState | None = None,
    require_live_proof: bool = False,
) -> DeviceAwareDryRun:
    """Build one complete offline dry run from beginner parameters to semantic change plan."""
    design = build_device_aware_design_preview(
        request,
        profile,
        observed_state=observed_state,
        require_live_proof=require_live_proof,
    )
    plan = build_change_plan(
        design.template_result.intent,
        current_state,
        device_profile=profile,
        security_expansion=design.security_expansion,
    )
    return DeviceAwareDryRun(design=design, plan=plan)
