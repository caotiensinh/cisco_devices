"""Offline workflow helpers that bind planning to the exact observed device profile.

These helpers remove a dangerous caller choice: an observed device cannot be planned against
an arbitrary or historical firmware profile. The exact product_id + firmware_version from
``ObservedState`` selects the repository profile, and unknown combinations fail closed.

This module performs no network/device access, emits no CLI, and grants no execution authority.
"""
from __future__ import annotations

from .current_state import CurrentNetworkState
from .dry_run import DeviceAwareDryRun, build_device_aware_dry_run
from .models import ObservedState
from .profile_registry import load_exact_profile
from .profiles import DeviceProfile
from .templates import TemplateRequest
from .workflow import DeviceAwareDesignPreview, build_device_aware_design_preview


def profile_for_observed_state(observed_state: ObservedState) -> DeviceProfile:
    """Load only the profile matching the observed product and firmware exactly."""
    fingerprint = observed_state.fingerprint
    return load_exact_profile(
        fingerprint.product_id,
        fingerprint.firmware_version,
    )


def build_exact_observed_design_preview(
    request: TemplateRequest,
    observed_state: ObservedState,
    *,
    require_live_proof: bool = False,
) -> DeviceAwareDesignPreview:
    """Build an offline design preview using the exact observed product/firmware profile."""
    profile = profile_for_observed_state(observed_state)
    return build_device_aware_design_preview(
        request,
        profile,
        observed_state=observed_state,
        require_live_proof=require_live_proof,
    )


def build_exact_observed_dry_run(
    request: TemplateRequest,
    current_state: CurrentNetworkState,
    observed_state: ObservedState,
    *,
    require_live_proof: bool = False,
) -> DeviceAwareDryRun:
    """Build an offline dry run with profile selection bound to observed identity."""
    profile = profile_for_observed_state(observed_state)
    return build_device_aware_dry_run(
        request,
        profile,
        current_state,
        observed_state=observed_state,
        require_live_proof=require_live_proof,
    )
