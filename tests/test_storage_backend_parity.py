from __future__ import annotations

import os
import sqlite3
from copy import deepcopy
from pathlib import Path
from uuid import uuid4
from zipfile import ZIP_DEFLATED, ZipFile

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

import pytest
from access_review_engine.application import persist_import_result
from access_review_engine.domain import (
    AccessAssignment,
    AccessRelation,
    AuditEvent,
    Campaign,
    DecisionValue,
    ExpectedAccessModel,
    Origin,
    OwnerRef,
    PermissionCapabilityMapping,
    stable_checksum,
)
from access_review_engine.importers.ad import import_ad_zip
from access_review_engine.importers.keycloak import import_keycloak_zip
from access_review_engine.importers.openldap import import_openldap_ldif
from access_review_engine.services import (
    close_campaign,
    create_decision,
    create_golden_source,
    open_campaign,
    promote_snapshot,
    remediation_from_decisions,
)
from access_review_engine.storage import Repository
from access_review_engine.system_admin import (
    ensure_bootstrap_user,
    external_user_api_enabled,
    init_system,
    set_external_user_api_enabled,
)


def test_database_url_keeps_legacy_paths_and_prefers_standard_environment(monkeypatch, tmp_path):
    from access_review_engine.database import database_url

    legacy_path = tmp_path / "legacy.db"
    assert database_url(legacy_path) == f"sqlite:///{legacy_path}"
    monkeypatch.setenv("EARE_DB_PATH", str(legacy_path))
    assert database_url() == f"sqlite:///{legacy_path}"
    monkeypatch.setenv("EARE_DATABASE_URL", "postgresql+psycopg://eare:test-password@db/eare")
    assert database_url() == "postgresql+psycopg://eare:test-password@db/eare"


@pytest.fixture(
    params=("sqlite", pytest.param("postgresql", marks=pytest.mark.postgres)),
    ids=("sqlite", "postgresql"),
)
def repository(request: pytest.FixtureRequest, tmp_path):
    if request.param == "sqlite":
        repo = Repository(tmp_path / "contract.db")
        try:
            yield repo
        finally:
            repo.close()
        return

    base_url = os.environ.get("EARE_TEST_POSTGRES_URL")
    if not base_url:
        pytest.skip("Set EARE_TEST_POSTGRES_URL to run PostgreSQL contract tests")
    schema = f"eare_test_{uuid4().hex}"
    admin_engine = create_engine(base_url, hide_parameters=True)
    schema_created = False
    try:
        with admin_engine.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        schema_created = True
        scoped_url = make_url(base_url).update_query_dict(
            {"options": f"-csearch_path={schema}"}
        )
        repo = Repository(scoped_url.render_as_string(hide_password=False))
        try:
            yield repo
        finally:
            repo.close()
    finally:
        try:
            if schema_created:
                with admin_engine.begin() as connection:
                    connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        finally:
            admin_engine.dispose()


def test_repository_contract(repository: Repository) -> None:
    provider = {"id": "provider-1", "name": "contract", "type": "test", "created_at": "2026-01-01"}
    repository.upsert("providers", provider)
    repository.upsert("providers", provider | {"display_name": "Updated"})
    assert repository.get_payload("providers", "provider-1")["display_name"] == "Updated"
    assert repository.find_by_name("providers", "contract")["id"] == "provider-1"
    assert repository.list_payloads_by_provider("accesses", "missing") == []
    assert [row["id"] for row in repository.list_payloads("providers")] == ["provider-1"]

    append_only = {"id": "version-1", "name": "golden", "version": 1}
    repository.insert_append_only("golden_source_versions", append_only)
    assert repository.find_version("golden", 1) == append_only
    if repository.conn.dialect_name == "sqlite":
        expected_error = sqlite3.IntegrityError
    else:
        import psycopg

        expected_error = psycopg.errors.UniqueViolation
    with pytest.raises(expected_error):
        repository.upsert("providers", {"id": "provider-duplicate", "name": "contract"})
    with pytest.raises(expected_error):
        repository.insert_append_only("golden_source_versions", append_only)
    with pytest.raises(expected_error):
        with repository.transaction():
            repository.upsert("providers", {"id": "provider-rollback", "name": "rollback"})
            repository.insert_append_only("golden_source_versions", append_only)
    assert repository.get_payload("providers", "provider-rollback") is None

    before = repository.list_payloads("providers")
    with pytest.raises(RuntimeError):
        with repository.transaction():
            repository.upsert("providers", provider | {"display_name": "rolled back"})
            raise RuntimeError("rollback")
    assert repository.list_payloads("providers") == before

    repository.delete_ids("providers", {"provider-1"})
    assert repository.get_payload("providers", "provider-1") is None

    assignment = AccessAssignment(
        "ldap", "finance", "ldap", "alice", Origin("group", True, False, "test")
    )
    repository.replace_assignments([assignment], providers={"ldap"})
    assert (
        repository.list_payloads_by_provider("access_assignments", "ldap")[0]["id"] == assignment.id
    )
    relation = AccessRelation(
        "ldap", "finance", "ldap", "read", "grants", Origin("relation", False, True, "test")
    )
    repository.replace_access_relations([relation], providers={"ldap"})
    assert repository.list_payloads_by_provider("access_relations", "ldap")[0]["id"] == relation.id

    capability_mapping = PermissionCapabilityMapping("ldap", "read", ("read",))
    repository.save_permission_capability_mapping(capability_mapping)
    assert repository.list_permission_capability_mappings() == [capability_mapping]
    repository.save_snapshot_functional_models(
        "snapshot-1",
        "import-1",
        [ExpectedAccessModel("ldap", "finance", "partial")],
        authoritative=False,
    )
    assert (
        repository.load_snapshot_functional_models("snapshot-1")[0]["snapshot_id"] == "snapshot-1"
    )


def test_system_capabilities_are_idempotent(repository: Repository) -> None:
    initial = repository.list_payloads("capabilities")
    capability_id = initial[0]["id"]
    replacement_payload = '{"id":"preserve-existing-payload"}'
    repository.conn.execute(
        "UPDATE capabilities SET payload = :payload WHERE id = :id",
        {"payload": replacement_payload, "id": capability_id},
    )
    repository.conn.commit()
    repository.init_schema()
    rows = repository.list_payloads("capabilities")
    assert len(rows) == len(initial)
    assert repository.get_payload("capabilities", capability_id) == {
        "id": "preserve-existing-payload"
    }


def test_system_administration_schema_uses_the_configured_backend(repository: Repository) -> None:
    from access_review_engine.database import connect_database

    database_uri = repository.engine.url.render_as_string(hide_password=False)
    with connect_database(database_uri) as connection:
        init_system(connection)
        ensure_bootstrap_user(connection)
        assert not external_user_api_enabled(connection)
        set_external_user_api_enabled(connection, True)
        assert external_user_api_enabled(connection)


def test_semantic_parity_for_canonical_payload_and_ordering(repository: Repository) -> None:
    records = [
        {
            "id": "b",
            "provider": "ldap",
            "name": "z",
            "created_at": "2026-02-01",
            "metadata": {"groups": ["a", "b"]},
        },
        {
            "id": "a",
            "provider": "ldap",
            "name": "a",
            "created_at": "2026-01-01",
            "metadata": {"groups": []},
        },
    ]
    for record in records:
        repository.upsert("accesses", record)
    result = repository.list_payloads_by_provider("accesses", "ldap")
    assert [row["id"] for row in result] == ["a", "b"]
    assert result[1]["metadata"] == {"groups": ["a", "b"]}
    assert repository.get_payload("accesses", "b") == records[0]


@pytest.mark.parametrize("source_type", ("keycloak", "openldap", "active_directory"))
def test_import_golden_campaign_review_and_audit_semantic_parity(
    repository: Repository, tmp_path, monkeypatch, source_type: str
) -> None:
    import access_review_engine.application as application

    if source_type == "keycloak":
        fixture_directory = Path(__file__).parent / "fixtures" / "keycloak"
        artifact = tmp_path / "keycloak-parity.zip"
        with ZipFile(artifact, "w", ZIP_DEFLATED) as archive:
            for item in sorted(fixture_directory.iterdir()):
                archive.write(item, item.name)
        imported = import_keycloak_zip(artifact)
    elif source_type == "openldap":
        imported = import_openldap_ldif(
            Path(__file__).parent / "UAT" / "CrashTests-OpenLDAP" / "fixture.ldif",
            provider_name="crashtests-openldap",
        )
    else:
        fixture_directory = (
            Path(__file__).parents[1] / "fixtures" / "raw" / "active-directory" / "standard"
        )
        artifact = tmp_path / "active-directory-parity.zip"
        with ZipFile(artifact, "w", ZIP_DEFLATED) as archive:
            for item in sorted(fixture_directory.iterdir()):
                archive.write(item, item.name)
        imported = import_ad_zip(artifact)

    original_create_snapshot = application.create_snapshot

    def create_stable_snapshot(*args, **kwargs):
        snapshot = original_create_snapshot(*args, **kwargs)
        snapshot.id = "snapshot-parity"
        return snapshot

    monkeypatch.setattr(application, "create_snapshot", create_stable_snapshot)
    mirror = Repository(tmp_path / "sqlite-parity.db")
    try:

        if source_type == "openldap":
            # This fixture is intentionally scoped/incomplete, and EARE correctly
            # forbids promoting such a snapshot to Golden Source.
            actual = persist_import_result(repository, deepcopy(imported))
            expected = persist_import_result(mirror, deepcopy(imported))
            assert actual.checksum == expected.checksum
            for table in (
                "providers",
                "identities",
                "accesses",
                "access_assignments",
                "access_relations",
                "snapshots",
                "snapshot_functional_access_models",
            ):
                assert repository.list_payloads(table) == mirror.list_payloads(table)
            return

        def run_lifecycle(target: Repository) -> None:
            snapshot = persist_import_result(target, deepcopy(imported))
            golden = create_golden_source("parity-golden", "Parity Golden")
            golden.id = "golden-parity"
            golden.created_at = "2026-01-01T00:00:00+00:00"
            target.upsert("golden_sources", golden)
            version = promote_snapshot(golden, snapshot)
            version.id = "golden-version-parity"
            version.created_at = "2026-01-01T00:00:00+00:00"
            target.insert_append_only("golden_source_versions", version)
            golden.active_version_id = version.id
            target.upsert("golden_sources", golden)

            reviewer = OwnerRef(imported.provider.name, "reviewer")
            campaign = Campaign(
                "parity-review",
                snapshot.id,
                golden_source_version_id=version.id,
                manager=reviewer,
                default_reviewer=reviewer,
                id="campaign-parity",
                created_at="2026-01-01T00:00:00+00:00",
            )
            opened, items = open_campaign(campaign, snapshot)
            opened.opened_at = "2026-01-01T00:00:00+00:00"
            for item in items:
                item.id = "review-" + stable_checksum(
                    (
                        item.access_provider,
                        item.access_name,
                        item.identity_provider,
                        item.identity_identifier,
                    )
                )
            if items:
                items[0].id = "review-parity-revoked"
            target.upsert("campaigns", opened)
            for item in items:
                target.upsert("review_items", item)
            decisions = []
            for index, item in enumerate(items):
                value = DecisionValue.REVOKE if index == 0 else DecisionValue.APPROVE
                decision = create_decision(
                    item,
                    value,
                    "Parity test revocation" if value == DecisionValue.REVOKE else None,
                    "reviewer",
                )
                decision.id = "decision-" + item.id
                decision.created_at = "2026-01-01T00:00:00+00:00"
                target.insert_append_only("decisions", decision)
                decisions.append(decision)
            closed = close_campaign(opened, items, decisions)
            closed.closed_at = "2026-01-01T00:00:00+00:00"
            target.upsert("campaigns", closed)
            actions = remediation_from_decisions(items, decisions)
            for action in actions:
                action.id = "remediation-" + action.review_item_id
                action.created_at = "2026-01-01T00:00:00+00:00"
                target.insert_append_only("remediation_actions", action)
            target.insert_append_only(
                "audit_events",
                AuditEvent(
                    "parity.lifecycle",
                    actor="reviewer",
                    object_type="campaign",
                    object_id=opened.id,
                    id="audit-parity",
                    created_at="2026-01-01T00:00:00+00:00",
                ),
            )

        run_lifecycle(repository)
        run_lifecycle(mirror)

        def semantic_state(target: Repository) -> dict[str, object]:
            table_names = (
                "providers",
                "identities",
                "accesses",
                "access_assignments",
                "access_relations",
                "imports",
                "snapshots",
                "snapshot_functional_access_models",
                "golden_sources",
                "golden_source_versions",
                "campaigns",
                "review_items",
                "decisions",
                "remediation_actions",
                "audit_events",
            )

            def stable(value):
                if isinstance(value, dict):
                    return {
                        key: (
                            "<timestamp>"
                            if key in {"created_at", "started_at", "completed_at"}
                            else stable(item)
                        )
                        for key, item in value.items()
                    }
                if isinstance(value, list):
                    return [stable(item) for item in value]
                return value

            return {table: stable(target.list_payloads(table)) for table in table_names}

        assert semantic_state(repository) == semantic_state(mirror)
        assert (
            repository.list_payloads("snapshots")[0]["checksum"]
            == mirror.list_payloads("snapshots")[0]["checksum"]
        )
        assert (
            repository.list_payloads("golden_source_versions")[0]["checksum"]
            == mirror.list_payloads("golden_source_versions")[0]["checksum"]
        )
    finally:
        mirror.close()


def test_postgresql_concurrency(repository: Repository) -> None:
    """Exercise independent sessions, read visibility and a unique-key race."""
    if repository.conn.dialect_name != "postgresql":
        pytest.skip("PostgreSQL-specific concurrency coverage")
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    import psycopg
    from sqlalchemy import create_engine, text

    url = repository.engine.url.render_as_string(hide_password=False)
    engine = create_engine(url, hide_parameters=True)
    suffix = uuid4().hex
    created = Event()
    finish_write = Event()

    def writer() -> None:
        with Repository(url) as repo:
            with repo.transaction():
                repo.upsert("audit_events", {"id": f"uncommitted-{suffix}"})
                created.set()
                assert finish_write.wait(10)

    def reader_during_write() -> bool:
        assert created.wait(10)
        with engine.connect() as connection:
            return (
                connection.execute(
                    text("SELECT payload FROM audit_events WHERE id = :id"),
                    {"id": f"uncommitted-{suffix}"},
                ).first()
                is None
            )

    with ThreadPoolExecutor(max_workers=2) as pool:
        writer_future = pool.submit(writer)
        reader_future = pool.submit(reader_during_write)
        assert reader_future.result(timeout=15)
        finish_write.set()
        writer_future.result(timeout=15)

    def read_events() -> int:
        with engine.connect() as connection:
            return int(connection.execute(text("SELECT count(*) FROM audit_events")).scalar_one())

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(lambda _: read_events(), range(2))) == [1, 1]

    def independent_write(record_id: str) -> None:
        with Repository(url) as repo:
            repo.upsert("audit_events", {"id": record_id, "event_type": "parallel"})

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(independent_write, (f"independent-{suffix}-1", f"independent-{suffix}-2")))
    assert read_events() == 3

    def insert_provider(record_id: str) -> str:
        try:
            with Repository(url) as repo:
                repo.upsert(
                    "providers", {"id": record_id, "name": f"race-{suffix}", "type": "test"}
                )
            return "inserted"
        except psycopg.errors.UniqueViolation:
            return "duplicate"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(insert_provider, (f"race-{suffix}-1", f"race-{suffix}-2")))
    assert sorted(results) == ["duplicate", "inserted"]
    with engine.connect() as connection:
        assert (
            connection.execute(
                text("SELECT count(*) FROM providers WHERE name = :name"),
                {"name": f"race-{suffix}"},
            ).scalar_one()
            == 1
        )
    engine.dispose()
