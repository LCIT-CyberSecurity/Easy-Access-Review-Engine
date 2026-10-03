from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection, create_engine

from access_review_engine.database import database_url
from access_review_engine.storage import repository_metadata

config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)

target_metadata = repository_metadata()[0]


def run_migrations_offline() -> None:
    context.configure(
        url=database_url(os.environ.get("EARE_DATABASE_URL")),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    url = database_url(os.environ.get("EARE_DATABASE_URL"))
    connectable = create_engine(url, poolclass=pool.NullPool, hide_parameters=True)
    with connectable.connect() as connection:
        do_run_migrations(connection)
    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
