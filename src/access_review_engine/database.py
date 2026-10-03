"""SQLAlchemy Core database configuration shared by persistence components."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any

from sqlalchemy import Connection, Engine, create_engine, text
from sqlalchemy.engine import make_url


def database_url(value: str | Path | None = None) -> str:
    """Resolve a configured URL or a legacy filesystem path to a SQLAlchemy URL."""
    if value is None:
        import os

        configured = os.environ.get("EARE_DATABASE_URL")
        if configured:
            return configured
        configured = os.environ.get("EARE_DB_PATH")
        value = configured or "access-review.db"
    raw = str(value)
    if "://" in raw:
        return raw
    return f"sqlite:///{Path(raw).expanduser().resolve().as_posix()}"


def make_engine(value: str | Path | None = None) -> Engine:
    url = database_url(value)
    options: dict[str, Any] = {"pool_pre_ping": True, "hide_parameters": True}
    if url.startswith("sqlite:"):
        options["connect_args"] = {"timeout": 30, "check_same_thread": False}
    return create_engine(url, **options)


def sqlite_database_path(value: str | Path | None = None) -> Path | None:
    """Return a file-backed SQLite path, or None for non-SQLite/in-memory URLs."""
    url = make_url(database_url(value))
    if not url.drivername.startswith("sqlite") or not url.database or url.database == ":memory:":
        return None
    return Path(url.database).expanduser().resolve()


def _named_parameters(
    sql: str, values: Iterable[Any] | Mapping[str, Any] | None
) -> tuple[str, Any]:
    if values is None or isinstance(values, Mapping):
        return sql, values or {}
    params = tuple(values)
    index = 0
    output: list[str] = []
    quote: str | None = None
    for char in sql:
        if quote:
            output.append(char)
            if char == quote:
                quote = None
        elif char in ("'", '"'):
            quote = char
            output.append(char)
        elif char == "?":
            output.append(f":p{index}")
            index += 1
        else:
            output.append(char)
    if index != len(params):
        raise ValueError("SQL parameter count does not match placeholders")
    return "".join(output), {f"p{i}": value for i, value in enumerate(params)}


class Result:
    """Small mapping-row adapter preserving the Repository's existing row API."""

    def __init__(self, result: Any) -> None:
        self._result = result

    @staticmethod
    def _mapping(row: Any) -> Any:
        return CompatibleRow(row) if row is not None else None

    def fetchone(self) -> Any:
        return self._mapping(self._result.fetchone())

    def fetchall(self) -> list[Any]:
        return [self._mapping(row) for row in self._result.fetchall()]

    def __iter__(self) -> Iterator[Any]:
        return iter(self.fetchall())

    @property
    def rowcount(self) -> int:
        return int(self._result.rowcount)


class CompatibleRow:
    """Support the named and positional row access used by legacy callers."""

    def __init__(self, row: Any) -> None:
        self._row = row
        self._mapping = row._mapping

    def __getitem__(self, key: Any) -> Any:
        return self._row[key] if isinstance(key, int) else self._mapping[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self._mapping.get(key, default)

    def keys(self) -> Any:
        return self._mapping.keys()


class DatabaseConnection:
    """Connection adapter for the existing synchronous persistence API."""

    def __init__(self, connection: Connection, engine: Engine | None = None) -> None:
        self.raw = connection
        self._engine = engine

    @property
    def dialect_name(self) -> str:
        return self.raw.dialect.name

    def execute(
        self, statement: Any, parameters: Iterable[Any] | Mapping[str, Any] | None = None
    ) -> Result:
        try:
            if isinstance(statement, str):
                sql, values = _named_parameters(statement, parameters)
                result = self.raw.execute(text(sql), values)
            else:
                if parameters is not None and not isinstance(parameters, Mapping):
                    raise TypeError("SQLAlchemy Core statements require named parameters")
                result = self.raw.execute(statement, parameters or {})
            return Result(result)
        except Exception as exc:
            self.raw.rollback()
            original = getattr(exc, "orig", None)
            if original is not None:
                raise original from exc
            raise

    def commit(self) -> None:
        if self.raw.in_transaction():
            self.raw.commit()

    def rollback(self) -> None:
        if self.raw.in_transaction():
            self.raw.rollback()

    def close(self) -> None:
        self.raw.close()
        if self._engine is not None:
            self._engine.dispose()

    def __enter__(self) -> DatabaseConnection:
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if exc_type is None:
            self.commit()
        else:
            self.rollback()
        if self._engine is not None:
            self.close()


def safe_identifier(identifier: str, allowed: set[str]) -> str:
    if identifier not in allowed or not re.fullmatch(r"[a-z_][a-z0-9_]*", identifier):
        raise ValueError("Unknown persistence table")
    return identifier


def connect_database(value: str | Path | None = None) -> DatabaseConnection:
    engine = make_engine(value)
    return DatabaseConnection(engine.connect(), engine)
