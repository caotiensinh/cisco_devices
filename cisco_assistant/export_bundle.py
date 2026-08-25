"""Deterministic local export bundle for offline dry-run evidence.

The exporter writes only already-normalized dry-run data. It has no device/network access and
contains no credential/session model fields.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from .dry_run import DeviceAwareDryRun


EXPORT_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class ExportedFile:
    name: str
    sha256: str
    bytes: int

    def as_dict(self) -> dict[str, object]:
        return {"name": self.name, "sha256": self.sha256, "bytes": self.bytes}


@dataclass(frozen=True, slots=True)
class DryRunExportManifest:
    schema_version: int
    status: str
    plan_hash: str
    files: tuple[ExportedFile, ...]
    execution_authority: bool = False
    device_commands_generated: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "plan_hash": self.plan_hash,
            "execution_authority": self.execution_authority,
            "device_commands_generated": self.device_commands_generated,
            "files": [item.as_dict() for item in self.files],
        }


@dataclass(frozen=True, slots=True)
class DryRunExportResult:
    output_directory: str
    manifest: DryRunExportManifest
    json_path: str
    text_path: str
    manifest_path: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _atomic_write(path: Path, data: bytes) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(data)
    temporary.replace(path)


def export_dry_run_bundle(
    result: DeviceAwareDryRun,
    output_directory: str | Path,
) -> DryRunExportResult:
    """Export deterministic JSON/text dry-run evidence and a hash manifest."""
    output = Path(output_directory)
    output.mkdir(parents=True, exist_ok=True)
    if not output.is_dir():
        raise ValueError(f"Output path is not a directory: {output}")

    json_bytes = (
        json.dumps(
            result.as_dict(),
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")
    text_bytes = (result.render_text() + "\n").encode("utf-8")

    json_name = "network_dry_run.json"
    text_name = "network_dry_run.txt"
    manifest_name = "manifest.json"

    files = (
        ExportedFile(json_name, _sha256(json_bytes), len(json_bytes)),
        ExportedFile(text_name, _sha256(text_bytes), len(text_bytes)),
    )
    manifest = DryRunExportManifest(
        schema_version=EXPORT_SCHEMA_VERSION,
        status=result.status,
        plan_hash=result.plan.plan_hash,
        files=files,
    )
    manifest_bytes = (
        json.dumps(manifest.as_dict(), sort_keys=True, indent=2, ensure_ascii=False)
        + "\n"
    ).encode("utf-8")

    json_path = output / json_name
    text_path = output / text_name
    manifest_path = output / manifest_name
    _atomic_write(json_path, json_bytes)
    _atomic_write(text_path, text_bytes)
    _atomic_write(manifest_path, manifest_bytes)

    return DryRunExportResult(
        output_directory=str(output),
        manifest=manifest,
        json_path=str(json_path),
        text_path=str(text_path),
        manifest_path=str(manifest_path),
    )
