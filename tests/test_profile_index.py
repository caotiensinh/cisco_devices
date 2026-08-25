import json
from pathlib import Path

import pytest

from cisco_assistant.profile_registry import (
    load_current_exact_live_profile,
    load_exact_profile,
    load_profile_references,
    select_exact_profile_reference,
)
from cisco_assistant.profiles import ProfileError, load_device_profile


ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "knowledge" / "cbs250" / "profiles" / "index.json"


def test_profile_index_exact_live_reference_is_resolvable_and_write_free():
    index = json.loads(INDEX.read_text(encoding="utf-8"))
    assert index["schema_version"] == 1
    assert index["device_write_authority"] is False

    current = index["current_exact_live_reference"]
    profile_path = ROOT / current["profile_path"]
    evidence_path = ROOT / current["evidence_path"]
    assert profile_path.is_file()
    assert evidence_path.is_file()

    profile = load_device_profile(profile_path)
    assert profile.fingerprint.product_id == current["product_id"]
    assert profile.fingerprint.firmware_version == current["firmware_version"]
    assert current["firmware_version"] == "3.5.3.3"
    assert current["coverage_status"] == "TRUNCATED_AT_MAX_NODES"


def test_historical_profile_is_not_current_reference():
    index = json.loads(INDEX.read_text(encoding="utf-8"))
    current = index["current_exact_live_reference"]
    historical = index["historical_profiles"]

    assert current["firmware_version"] == "3.5.3.3"
    assert any(item["firmware_version"] == "3.3.0.16" for item in historical)
    assert all(item["profile_path"] != current["profile_path"] for item in historical)
    assert "exact product_id + firmware_version" in index["selection_rule"]
    assert "fails closed" in index["selection_rule"]


def test_runtime_exact_selector_uses_current_3533_and_can_resolve_historical_only_exactly():
    refs = load_profile_references()
    assert len(tuple(ref for ref in refs if ref.current)) == 1

    current = load_current_exact_live_profile()
    assert current.fingerprint.product_id == "CBS250-24T-4X"
    assert current.fingerprint.firmware_version == "3.5.3.3"

    historical = load_exact_profile("CBS250-24T-4X", "3.3.0.16")
    assert historical.fingerprint.firmware_version == "3.3.0.16"
    assert historical.profile_id != current.profile_id


def test_runtime_exact_selector_forbids_cross_firmware_fallback():
    with pytest.raises(ProfileError, match="cross-firmware fallback is forbidden"):
        load_exact_profile("CBS250-24T-4X", "3.4.0.0")

    with pytest.raises(ProfileError, match="cross-firmware fallback is forbidden"):
        select_exact_profile_reference("CBS250-24T-4X", "9.9.9.9")

    with pytest.raises(ProfileError, match="requires product_id and firmware_version"):
        select_exact_profile_reference("CBS250-24T-4X", "")
