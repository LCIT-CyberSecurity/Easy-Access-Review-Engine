from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url

import pytest
from access_review_engine.database import connect_database
from access_review_engine.storage import TABLES, Repository
from access_review_engine.system_admin import init_system

SYSTEM_TABLES = {
    "system_users",
    "identity_provider_configs",
    "system_settings",
    "api_tokens",
    "mcp_tokens",
    "web_jobs",
    "web_job_events",
}


@pytest.mark.postgres
def test_alembic_initial_schema_is_usable_on_postgresql() -> None:
    base_url = os.environ.get("EARE_TEST_POSTGRES_URL")
    if not base_url:
        pytest.skip("Set EARE_TEST_POSTGRES_URL to run PostgreSQL Alembic tests")
    assert base_url is not None

    schema = "eare_alembic_test"
    admin_engine = create_engine(base_url, hide_parameters=True)
    repository_url = (
        make_url(base_url)
        .update_query_dict({"options": f"-csearch_path={schema}"})
        .render_as_string(hide_password=False)
    )
    environment = os.environ.copy()
    environment["EARE_DATABASE_URL"] = repository_url
    root = Path(__file__).parents[1]
    try:
        with admin_engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))

        subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=root,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        current = subprocess.run(
            [sys.executable, "-m", "alembic", "current"],
            cwd=root,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        assert "0001_repository_schema" in current.stdout + current.stderr

        engine = create_engine(repository_url, hide_parameters=True)
        try:
            tables = set(inspect(engine).get_table_names(schema=schema))
        finally:
            engine.dispose()
        assert set(TABLES) | SYSTEM_TABLES <= tables

        db_connection = connect_database(repository_url)
        try:
            init_system(db_connection)
        finally:
            db_connection.close()

        with Repository(repository_url) as repository:
            repository.upsert(
                "providers",
                {"id": "alembic-provider", "name": "alembic", "type": "test"},
            )
            provider = repository.find_by_name("providers", "alembic")
            assert provider is not None
            assert provider["id"] == "alembic-provider"
    finally:
        with admin_engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        admin_engine.dispose()
