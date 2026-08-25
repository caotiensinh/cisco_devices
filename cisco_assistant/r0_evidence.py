"""Fail-closed offline ingestion for CBS250 R0 candidate command evidence.

This module never opens a network connection and never executes a device command. It accepts
externally captured command output, binds it to the exact reviewed product/firmware candidate,
and returns digest-only metadata. Raw output is intentionally not retained in the returned
record and ingestion never promotes a command into the executable allowlist.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any


CANDIDATE_REVIEW_PATH = "knowledge/cbs250/r0_candidate_review_3.5.3.3.json"
READY_STATUS = "READY_FOR_CONTROLLED_LIVE_READ_VALIDATION"
INGESTED_STATUS = "INGESTED_UNVERIFIED"


class R0EvidenceError(ValueError):
    """Raised when external evidence cannot be safely accepted for offline review."""


@dataclass(frozen=True, slots=True)
class R0Candidate:
    command: str
    risk_class: str
    review_status: str
    evidence_sensitivity: str
    expected_use: str


@dataclass(frozen=True, slots=True)
class R0EvidenceRecord:
    command: str
    product_id: str
    firmware_version: str
    raw_text_sha256: str
    raw_text_bytes: int
    canonical_text_sha256: str
    canonical_text_bytes: int
    source_label: str
    candidate_review_status: str
    evidence_sensitivity: str
    verification_status: str = INGESTED_STATUS
    device_write_authority: bool = False
    execution_authority: bool = False
    promoted_to_execution_allowlist: bool = False
    raw_output_retained: bool = False
    raw_output_commit_allowed: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "command": self.command,
            "product_id": self.product_id,
            "firmware_version": self.firmware_version,
            "raw_text_sha256": self.raw_text_sha256,
            "raw_text_bytes": self.raw_text_bytes,
            "canonical_text_sha256": self.canonical_text_sha256,
            "canonical_text_bytes": self.canonical_text_bytes,
            "source_label": self.source_label,
            "candidate_review_status": self.candidate_review_status,
            "evidence_sensitivity": self.evidence_sensitivity,
            "verification_status": self.verification_status,
            "device_write_authority": False,
            "execution_authority": False,
            "promoted_to_execution_allowlist": False,
            "raw_output_retained": False,
            "raw_output_commit_allowed": False,
        }


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _required_text(value: str, field_name: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise R0EvidenceError(f"{field_name} must not be empty")
    return normalized


def _load_review_payload(path: str | Path = CANDIDATE_REVIEW_PATH) -> dict[str, Any]:
    review_path = Path(path)
    if not review_path.is_absolute():
        review_path = _repo_root() / review_path
    try:
        payload = json.loads(review_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise R0EvidenceError(f"Cannot load R0 candidate review {review_path}: {exc}") from exc

    if payload.get("schema_version") != 1:
        raise R0EvidenceError("Unsupported R0 candidate review schema_version")
    authority = payload.get("authority", {})
    if authority.get("device_write_authority") is not False:
        raise R0EvidenceError("R0 candidate review must not grant device write authority")
    if authority.get("candidate_review_grants_execution_authority") is not False:
        raise R0EvidenceError("R0 candidate review must not grant execution authority")
    return payload


def load_r0_candidates(path: str | Path = CANDIDATE_REVIEW_PATH) -> tuple[R0Candidate, ...]:
    payload = _load_review_payload(path)
    candidates: list[R0Candidate] = []
    seen: set[str] = set()
    for item in payload.get("candidates", []):
        try:
            candidate = R0Candidate(
                command=_required_text(str(item["command"]), "command"),
                risk_class=_required_text(str(item["risk_class"]), "risk_class"),
                review_status=_required_text(str(item["review_status"]), "review_status"),
                evidence_sensitivity=_required_text(
                    str(item["evidence_sensitivity"]), "evidence_sensitivity"
                ),
                expected_use=_required_text(str(item["expected_use"]), "expected_use"),
            )
        except (KeyError, TypeError) as exc:
            raise R0EvidenceError(f"Malformed R0 candidate entry: {exc}") from exc
        normalized = " ".join(candidate.command.split()).casefold()
        if normalized in seen:
            raise R0EvidenceError(f"Duplicate R0 candidate command: {candidate.command!r}")
        seen.add(normalized)
        if candidate.risk_class != "R0":
            raise R0EvidenceError(
                f"Candidate {candidate.command!r} is not classified R0: {candidate.risk_class!r}"
            )
        candidates.append(candidate)
    return tuple(candidates)


def _select_candidate(command: str, path: str | Path = CANDIDATE_REVIEW_PATH) -> R0Candidate:
    normalized = " ".join(_required_text(command, "command").split()).casefold()
    for candidate in load_r0_candidates(path):
        if " ".join(candidate.command.split()).casefold() == normalized:
            return candidate
    raise R0EvidenceError(
        f"Command {command!r} is not present in the reviewed R0 candidate registry"
    )


def ingest_external_r0_output(
    *,
    command: str,
    product_id: str,
    firmware_version: str,
    raw_output: str,
    source_label: str,
    review_path: str | Path = CANDIDATE_REVIEW_PATH,
) -> R0EvidenceRecord:
    """Create digest-only metadata for externally captured candidate output.

    The caller-supplied output is not independently proven live by this offline function.
    Therefore every record remains ``INGESTED_UNVERIFIED`` and cannot grant execution or
    allowlist authority. Commands on HOLD are rejected until their candidate review changes.

    ``raw_text_sha256`` fingerprints the text exactly as supplied to this function after UTF-8
    encoding. ``canonical_text_sha256`` normalizes CRLF/CR line endings to LF so independently
    exported Windows/Unix text can also be compared without losing the exact supplied digest.
    """
    payload = _load_review_payload(review_path)
    target = payload.get("target", {})
    expected_product = _required_text(str(target.get("product_id", "")), "target.product_id")
    expected_firmware = _required_text(str(target.get("firmware", "")), "target.firmware")

    product = _required_text(product_id, "product_id")
    firmware = _required_text(firmware_version, "firmware_version")
    if product.casefold() != expected_product.casefold() or firmware != expected_firmware:
        raise R0EvidenceError(
            "Evidence target does not match the exact candidate review target: "
            f"received={product}/{firmware}, expected={expected_product}/{expected_firmware}"
        )

    candidate = _select_candidate(command, review_path)
    if candidate.review_status != READY_STATUS:
        raise R0EvidenceError(
            f"Candidate {candidate.command!r} is not ready for controlled live read validation: "
            f"status={candidate.review_status}"
        )

    if not raw_output.strip():
        raise R0EvidenceError("raw_output must contain captured command output")
    label = _required_text(source_label, "source_label")

    raw_encoded = raw_output.encode("utf-8")
    canonical_output = raw_output.replace("\r\n", "\n").replace("\r", "\n")
    canonical_encoded = canonical_output.encode("utf-8")

    return R0EvidenceRecord(
        command=candidate.command,
        product_id=expected_product,
        firmware_version=expected_firmware,
        raw_text_sha256="sha256:" + hashlib.sha256(raw_encoded).hexdigest(),
        raw_text_bytes=len(raw_encoded),
        canonical_text_sha256="sha256:" + hashlib.sha256(canonical_encoded).hexdigest(),
        canonical_text_bytes=len(canonical_encoded),
        source_label=label,
        candidate_review_status=candidate.review_status,
        evidence_sensitivity=candidate.evidence_sensitivity,
    )
