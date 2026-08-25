import pytest

from cisco_assistant.template_migrations import (
    TemplateDocument,
    TemplateMigrationError,
    migrate_template_document,
)
from cisco_assistant.templates import TemplateId


def document(version="1.0.0"):
    return TemplateDocument(
        schema_version=1,
        template_id=TemplateId.SMALL_OFFICE,
        template_version=version,
        parameters={
            "start_vlan_id": 100,
            "start_network": "10.0.0.0/24",
        },
        metadata={"source": "unit-test"},
    )


def test_current_version_round_trip_is_stable_and_noop():
    source = document()
    first = migrate_template_document(source)
    second = migrate_template_document(source)

    assert first == second
    assert first.changed is False
    assert first.path == ("1.0.0",)
    assert first.document == source
    assert first.as_dict() == second.as_dict()


def test_unknown_schema_and_template_fail_closed():
    with pytest.raises(TemplateMigrationError, match="Unsupported template document schema_version"):
        TemplateDocument(
            schema_version=2,
            template_id="small_office",
            template_version="1.0.0",
            parameters={},
        )

    with pytest.raises(TemplateMigrationError, match="Unknown template_id"):
        TemplateDocument(
            schema_version=1,
            template_id="not-real",
            template_version="1.0.0",
            parameters={},
        )


def test_old_version_does_not_silently_migrate_without_registered_path():
    with pytest.raises(TemplateMigrationError, match="No explicit migration path"):
        migrate_template_document(document("0.9.0"))


def test_explicit_migration_edge_can_change_parameters_deterministically():
    source = document("0.9.0")

    def migrate_090_to_100(item):
        params = dict(item.parameters)
        params["vlan_increment"] = 10
        return TemplateDocument(
            schema_version=1,
            template_id=item.template_id,
            template_version="1.0.0",
            parameters=params,
            metadata=item.metadata,
        )

    registry = {
        (TemplateId.SMALL_OFFICE, "0.9.0", "1.0.0"): migrate_090_to_100,
    }
    result = migrate_template_document(source, registry=registry)

    assert result.changed is True
    assert result.path == ("0.9.0", "1.0.0")
    assert result.document.parameters["vlan_increment"] == 10
    assert result.document.parameters["start_vlan_id"] == 100
    assert result.document.metadata == source.metadata


def test_multi_hop_path_is_deterministic():
    source = document("0.8.0")

    def to_090(item):
        return TemplateDocument(
            schema_version=1,
            template_id=item.template_id,
            template_version="0.9.0",
            parameters={**item.parameters, "stage": "0.9.0"},
            metadata=item.metadata,
        )

    def to_100(item):
        return TemplateDocument(
            schema_version=1,
            template_id=item.template_id,
            template_version="1.0.0",
            parameters={**item.parameters, "stage": "1.0.0"},
            metadata=item.metadata,
        )

    registry = {
        (TemplateId.SMALL_OFFICE, "0.8.0", "0.9.0"): to_090,
        (TemplateId.SMALL_OFFICE, "0.9.0", "1.0.0"): to_100,
    }
    result = migrate_template_document(source, registry=registry)
    assert result.path == ("0.8.0", "0.9.0", "1.0.0")
    assert result.document.parameters["stage"] == "1.0.0"


def test_bad_migration_cannot_change_template_identity():
    source = document("0.9.0")

    def bad(item):
        return TemplateDocument(
            schema_version=1,
            template_id=TemplateId.CAMERA_VMS,
            template_version="1.0.0",
            parameters=item.parameters,
        )

    registry = {
        (TemplateId.SMALL_OFFICE, "0.9.0", "1.0.0"): bad,
    }
    with pytest.raises(TemplateMigrationError, match="change template_id"):
        migrate_template_document(source, registry=registry)


def test_bad_migration_must_produce_registered_target_version():
    source = document("0.9.0")

    def bad(item):
        return TemplateDocument(
            schema_version=1,
            template_id=item.template_id,
            template_version="0.9.1",
            parameters=item.parameters,
        )

    registry = {
        (TemplateId.SMALL_OFFICE, "0.9.0", "1.0.0"): bad,
    }
    with pytest.raises(TemplateMigrationError, match="registered target version"):
        migrate_template_document(source, registry=registry)
