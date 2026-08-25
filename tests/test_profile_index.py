import json
from pathlib import Path

from cisco_assistant.profiles import load_device_profile


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
