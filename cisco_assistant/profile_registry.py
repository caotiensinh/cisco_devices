"""Exact firmware-bound CBS250 capability-profile selection.

This module reads repository knowledge only. It performs no network/device access and grants
no execution authority. Profile selection always requires an exact product+firmware match;
historical profiles are never substituted for a different observed firmware.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from .profiles import DeviceProfile, ProfileError, load_device_profile


PROFILE_INDEX_PATH = "knowledge/cbs250/profiles/index.json"


@dataclass(frozen=True, slots=True)
class ProfileReference:
    product_id: str
    firmware_version: str
    profile_path: str
    evidence_path: str
    current: bool
    coverage_status: str | None = None


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_profile_references() -> tuple[ProfileReference, ...]:
    path = _repo_root() / PROFILE_INDEX_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProfileError(f"Cannot load exact-profile index {path}: {exc}") from exc

    if payload.get("schema_version") != 1:
        raise ProfileError("Unsupported exact-profile index schema_version")
    if payload.get("device_write_authority") is not False:
        raise ProfileError("Profile index must not grant device write authority")

    try:
        current = payload["current_exact_live_reference"]
        historical = payload.get("historical_profiles", [])
        refs = [
            ProfileReference(
                product_id=str(current["product_id"]),
                firmware_version=str(current["firmware_version"]),
                profile_path=str(current["profile_path"]),
                evidence_path=str(current["evidence_path"]),
                current=True,
                coverage_status=str(current.get("coverage_status"))
                if current.get("coverage_status") is not None
                else None,
            )
        ]
        refs.extend(
            ProfileReference(
                product_id=str(item["product_id"]),
                firmware_version=str(item["firmware_version"]),
                profile_path=str(item["profile_path"]),
                evidence_path=str(item["evidence_path"]),
                current=False,
            )
            for item in historical
        )
    except (KeyError, TypeError) as exc:
        raise ProfileError(f"Malformed exact-profile index: {exc}") from exc

    keys = [(ref.product_id.casefold(), ref.firmware_version) for ref in refs]
    if len(keys) != len(set(keys)):
        raise ProfileError("Duplicate product/firmware entries in exact-profile index")
    return tuple(refs)


def select_exact_profile_reference(product_id: str, firmware_version: str) -> ProfileReference:
    product = product_id.strip().casefold()
    firmware = firmware_version.strip()
    if not product or not firmware:
        raise ProfileError("Exact profile selection requires product_id and firmware_version")

    for ref in load_profile_references():
        if ref.product_id.casefold() == product and ref.firmware_version == firmware:
            return ref
    raise ProfileError(
        f"No exact capability profile for product_id={product_id!r}, firmware={firmware_version!r}; "
        "cross-firmware fallback is forbidden"
    )


def load_exact_profile(product_id: str, firmware_version: str) -> DeviceProfile:
    ref = select_exact_profile_reference(product_id, firmware_version)
    profile = load_device_profile(ref.profile_path)
    if profile.fingerprint.product_id.casefold() != ref.product_id.casefold():
        raise ProfileError("Profile index product_id does not match loaded profile")
    if profile.fingerprint.firmware_version != ref.firmware_version:
        raise ProfileError("Profile index firmware does not match loaded profile")
    return profile


def load_current_exact_live_profile() -> DeviceProfile:
    refs = tuple(ref for ref in load_profile_references() if ref.current)
    if len(refs) != 1:
        raise ProfileError(f"Expected exactly one current exact-live profile, found {len(refs)}")
    ref = refs[0]
    return load_exact_profile(ref.product_id, ref.firmware_version)
