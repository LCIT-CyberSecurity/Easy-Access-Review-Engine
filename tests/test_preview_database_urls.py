from __future__ import annotations

import os
from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

import pytest
from access_review_engine.storage import TABLES, Repository
from access_review_engine.web_use_cases import preview_import

OPENLDAP_FIXTURE = Path(__file__).parent / "UAT" / "CrashTests-OpenLDAP" / "fixture.ldif"


def _seed_source(database: str | Path) -> None:
    with Repository(database) as repository:
        repository.upsert(
            "providers",
            {
                "id": "provider-preview",
                "name": "preview-openldap",
                "type": "openldap",
                "created_at": "2026-01-01T00:00:00+00:00",
            },
        )
        repository.upsert(
            "golden_sources",
            {
                "id": "golden-preview",
                "name": "preview-golden",
                "display_name": "Preview Golden",
                "created_at": "2026-01-01T00:00:00+00:00",
            },
        )
        repository.upsert(
            "access_assignments",
            {
                "id": "assignment-preview",
                "provider": "preview-openldap",
                "access_name": "group:existing",
                "identity_provider": "preview-openldap",
                "identity_identifier": "alice",
                "origin": {
                    "assignment_type": "group",
                    "direct": False,
                    "inherited": True,
                    "source": "preview",
                    "raw": {"unresolved": True},
                },
            },
        )
        repository.insert_append_only(
            "audit_events",
            {
                "id": "audit-preview",
                "event_type": "preview.seed",
                "created_at": "2026-01-01T00:00:00+00:00",
            },
        )


def _state(database: str | Path) -> dict[str, list[dict[str, object]]]:
    with Repository(database) as repository:
        return {table: repository.list_payloads(table) for table in sorted(TABLES)}


def _assert_preview_isolated(database: str | Path) -> None:
    _seed_source(database)
    before = _state(database)

    result = preview_import(
        database,
        OPENLDAP_FIXTURE,
        provider="preview-openldap",
    )

    after = _state(database)
    assert result.tables
    assert result.objects
    assert before == after
    assert after["snapshots"] == before["snapshots"]
    assert after["golden_sources"] == before["golden_sources"]
    assert after["access_assignments"] == before["access_assignments"]
    assert after["audit_events"] == before["audit_events"]


def test_preview_import_with_legacy_sqlite_path(tmp_path: Path) -> None:
    _assert_preview_isolated(tmp_path / "source.db")


def test_preview_import_with_sqlite_url(tmp_path: Path) -> None:
    source = tmp_path / "source-url.db"
    _assert_preview_isolated(f"sqlite:///{source}")


@pytest.fixture
def postgres_source() -> Generator[str, None, None]:
    base_url = os.environ.get("EARE_TEST_POSTGRES_URL")
    if not base_url:
        pytest.skip("Set EARE_TEST_POSTGRES_URL to run PostgreSQL preview tests")
    assert base_url is not None
    schema = "eare_preview_test"
    admin_engine = create_engine(base_url, hide_parameters=True)
    try:
        with admin_engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        url = make_url(base_url).update_query_dict({"options": f"-csearch_path={schema}"})
        yield url.render_as_string(hide_password=False)
    finally:
        with admin_engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        admin_engine.dispose()


@pytest.mark.postgres
def test_preview_import_with_postgresql_url(postgres_source: str, tmp_path: Path) -> None:
    _assert_preview_isolated(postgres_source, tmp_path)
