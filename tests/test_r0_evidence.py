import json

import pytest

from cisco_assistant.r0_evidence import (
    INGESTED_STATUS,
    R0EvidenceError,
    ingest_external_r0_output,
    load_r0_candidates,
)


def test_candidate_registry_loads_without_granting_execution():
    candidates = load_r0_candidates()
    commands = {candidate.command for candidate in candidates}
    assert "show vlan" in commands
    assert "show interfaces status" in commands
    assert "show running-config brief" in commands
    assert "show lacp" in commands
    assert all(candidate.risk_class == "R0" for candidate in candidates)


def test_ready_candidate_ingestion_is_digest_only_and_unverified():
    raw = "show vlan\r\n1 default Gi1-24\r\nswitch#"
    record = ingest_external_r0_output(
        command="show vlan",
        product_id="CBS250-24T-4X",
        firmware_version="3.5.3.3",
        raw_output=raw,
        source_label="physical-switch-capture",
    )

    payload = record.as_dict()
    assert record.command == "show vlan"
    assert record.verification_status == INGESTED_STATUS
    assert record.output_sha256.startswith("sha256:")
    assert record.output_bytes > 0
    assert record.execution_authority is False
    assert record.device_write_authority is False
    assert record.promoted_to_execution_allowlist is False
    assert record.raw_output_retained is False
    assert record.raw_output_commit_allowed is False
    assert raw not in json.dumps(payload)
    assert "default" not in json.dumps(payload)


def test_line_ending_normalization_makes_digest_deterministic():
    common = dict(
        command="show interfaces status",
        product_id="CBS250-24T-4X",
        firmware_version="3.5.3.3",
        source_label="capture",
    )
    windows = ingest_external_r0_output(raw_output="a\r\nb\r\n", **common)
    unix = ingest_external_r0_output(raw_output="a\nb\n", **common)
    assert windows.output_sha256 == unix.output_sha256
    assert windows.output_bytes == unix.output_bytes


def test_exact_firmware_mismatch_is_blocked():
    with pytest.raises(R0EvidenceError, match="does not match the exact candidate review target"):
        ingest_external_r0_output(
            command="show vlan",
            product_id="CBS250-24T-4X",
            firmware_version="3.3.0.16",
            raw_output="captured output",
            source_label="wrong-firmware",
        )


def test_unknown_command_is_blocked_before_evidence_acceptance():
    with pytest.raises(R0EvidenceError, match="not present in the reviewed R0 candidate registry"):
        ingest_external_r0_output(
            command="show imaginary-state",
            product_id="CBS250-24T-4X",
            firmware_version="3.5.3.3",
            raw_output="captured output",
            source_label="unknown-command",
        )


def test_hold_sensitive_running_config_is_not_ingested():
    with pytest.raises(R0EvidenceError, match="not ready for controlled live read validation"):
        ingest_external_r0_output(
            command="show running-config brief",
            product_id="CBS250-24T-4X",
            firmware_version="3.5.3.3",
            raw_output="username example secret hidden",
            source_label="must-be-blocked",
        )


def test_selector_required_bare_lacp_is_not_ingested():
    with pytest.raises(R0EvidenceError, match="not ready for controlled live read validation"):
        ingest_external_r0_output(
            command="show lacp",
            product_id="CBS250-24T-4X",
            firmware_version="3.5.3.3",
            raw_output="captured output",
            source_label="must-be-blocked",
        )


def test_empty_output_is_rejected():
    with pytest.raises(R0EvidenceError, match="raw_output must contain"):
        ingest_external_r0_output(
            command="show vlan",
            product_id="CBS250-24T-4X",
            firmware_version="3.5.3.3",
            raw_output=" \r\n ",
            source_label="empty-output",
        )


def test_tampered_candidate_review_cannot_grant_write_or_execution_authority(tmp_path):
    review = {
        "schema_version": 1,
        "target": {"product_id": "CBS250-24T-4X", "firmware": "3.5.3.3"},
        "authority": {
            "device_write_authority": True,
            "candidate_review_grants_execution_authority": False,
        },
        "candidates": [],
    }
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(review), encoding="utf-8")

    with pytest.raises(R0EvidenceError, match="must not grant device write authority"):
        load_r0_candidates(path)

    review["authority"]["device_write_authority"] = False
    review["authority"]["candidate_review_grants_execution_authority"] = True
    path.write_text(json.dumps(review), encoding="utf-8")
    with pytest.raises(R0EvidenceError, match="must not grant execution authority"):
        load_r0_candidates(path)
