from argparse import Namespace
import json

import pytest

from cbs250_r0_evidence_ingest import build_metadata
from cisco_assistant.r0_evidence import R0EvidenceError


def args_for(path, **overrides):
    values = {
        "command": "show interfaces status",
        "input_file": str(path),
        "product_id": "CBS250-24T-4X",
        "firmware": "3.5.3.3",
        "source_label": "physical-capture",
        "metadata_output": "",
    }
    values.update(overrides)
    return Namespace(**values)


def test_cli_metadata_builder_does_not_export_raw_capture(tmp_path):
    raw = "show interfaces status\r\nge1 1G-Copper Full 1000 Enabled Off Up Disabled Off\r\nswitch#\r\n"
    capture = tmp_path / "show_interfaces_status.txt"
    capture.write_text(raw, encoding="utf-8", newline="")

    payload = build_metadata(args_for(capture))
    rendered = json.dumps(payload)

    assert payload["schema_version"] == 1
    assert payload["command"] == "show interfaces status"
    assert payload["firmware_version"] == "3.5.3.3"
    assert payload["input_filename"] == "show_interfaces_status.txt"
    assert payload["execution_authority"] is False
    assert payload["device_write_authority"] is False
    assert payload["raw_output_retained"] is False
    assert raw not in rendered
    assert "1G-Copper" not in rendered


def test_cli_metadata_builder_requires_existing_file(tmp_path):
    with pytest.raises(R0EvidenceError, match="does not exist"):
        build_metadata(args_for(tmp_path / "missing.txt"))


def test_cli_metadata_builder_rejects_cross_firmware_capture(tmp_path):
    capture = tmp_path / "show_interfaces_status.txt"
    capture.write_text("captured output\n", encoding="utf-8")

    with pytest.raises(R0EvidenceError, match="does not match the exact candidate review target"):
        build_metadata(args_for(capture, firmware="3.3.0.16"))
