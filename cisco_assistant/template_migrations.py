"""Explicit, deterministic migration contract for stored template parameter documents.

No migration is inferred from semantic similarity. A document changes version only when an
explicit migration edge exists for the same template ID. This module is offline-only and never
produces device CLI.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Mapping

from .templates import TEMPLATE_SCHEMA_VERSION, TemplateError, TemplateId, get_template_definition


class TemplateMigrationError(TemplateError):
    """Raised when a stored template document cannot be migrated explicitly and safely."""


@dataclass(frozen=True, slots=True)
class TemplateDocument:
    schema_version: int
    template_id: TemplateId | str
    template_version: str
    parameters: Mapping[str, object]
    metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.schema_version != TEMPLATE_SCHEMA_VERSION:
            raise TemplateMigrationError(
                f"Unsupported template document schema_version {self.schema_version}; "
                f"expected {TEMPLATE_SCHEMA_VERSION}"
            )
        try:
            normalized_id = (
                self.template_id
                if isinstance(self.template_id, TemplateId)
                else TemplateId(self.template_id)
            )
        except ValueError as exc:
            raise TemplateMigrationError(f"Unknown template_id {self.template_id!r}") from exc
        object.__setattr__(self, "template_id", normalized_id)
        version = self.template_version.strip()
        if not version:
            raise TemplateMigrationError("template_version must not be empty")
        object.__setattr__(self, "template_version", version)
        object.__setattr__(self, "parameters", dict(self.parameters))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "template_id": self.template_id.value,
            "template_version": self.template_version,
            "parameters": dict(self.parameters),
            "metadata": dict(self.metadata),
        }


MigrationFunction = Callable[[TemplateDocument], TemplateDocument]
MigrationKey = tuple[TemplateId, str, str]

# Production migrations are intentionally empty while every built-in template is 1.0.0.
# Future edges must be added explicitly, reviewed, and regression-tested.
TEMPLATE_MIGRATIONS: dict[MigrationKey, MigrationFunction] = {}


@dataclass(frozen=True, slots=True)
class TemplateMigrationResult:
    document: TemplateDocument
    source_version: str
    target_version: str
    path: tuple[str, ...]
    changed: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "source_version": self.source_version,
            "target_version": self.target_version,
            "path": list(self.path),
            "changed": self.changed,
            "document": self.document.as_dict(),
        }


def _find_path(
    template_id: TemplateId,
    source_version: str,
    target_version: str,
    registry: Mapping[MigrationKey, MigrationFunction],
) -> tuple[MigrationKey, ...] | None:
    if source_version == target_version:
        return ()

    adjacency: dict[str, list[str]] = {}
    for registered_template, source, target in registry:
        if registered_template is template_id:
            adjacency.setdefault(source, []).append(target)
    for targets in adjacency.values():
        targets.sort()

    queue = deque([(source_version, ())])
    visited = {source_version}
    while queue:
        version, path = queue.popleft()
        for next_version in adjacency.get(version, []):
            edge = (template_id, version, next_version)
            next_path = path + (edge,)
            if next_version == target_version:
                return next_path
            if next_version not in visited:
                visited.add(next_version)
                queue.append((next_version, next_path))
    return None


def migrate_template_document(
    document: TemplateDocument,
    *,
    target_version: str | None = None,
    registry: Mapping[MigrationKey, MigrationFunction] | None = None,
) -> TemplateMigrationResult:
    """Migrate a stored template document only through explicit registered edges."""
    current_definition = get_template_definition(document.template_id)
    desired_version = (target_version or current_definition.version).strip()
    if not desired_version:
        raise TemplateMigrationError("target_version must not be empty")

    migration_registry = TEMPLATE_MIGRATIONS if registry is None else registry
    path = _find_path(
        document.template_id,
        document.template_version,
        desired_version,
        migration_registry,
    )
    if path is None:
        raise TemplateMigrationError(
            f"No explicit migration path for {document.template_id.value}: "
            f"{document.template_version} -> {desired_version}"
        )

    result = document
    versions = [document.template_version]
    for edge in path:
        migration = migration_registry.get(edge)
        if migration is None:
            raise TemplateMigrationError(f"Migration edge disappeared during execution: {edge}")
        migrated = migration(result)
        expected_template, expected_source, expected_target = edge
        if migrated.template_id is not expected_template:
            raise TemplateMigrationError("Migration attempted to change template_id")
        if result.template_version != expected_source:
            raise TemplateMigrationError("Migration source version does not match current document")
        if migrated.template_version != expected_target:
            raise TemplateMigrationError(
                "Migration function did not produce the registered target version"
            )
        if migrated.schema_version != TEMPLATE_SCHEMA_VERSION:
            raise TemplateMigrationError("Migration changed unsupported schema_version")
        result = migrated
        versions.append(migrated.template_version)

    if result.template_version != desired_version:
        raise TemplateMigrationError("Migration path did not reach requested target version")

    return TemplateMigrationResult(
        document=result,
        source_version=document.template_version,
        target_version=desired_version,
        path=tuple(versions),
        changed=bool(path),
    )
