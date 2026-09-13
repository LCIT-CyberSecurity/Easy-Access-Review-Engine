"""Application use cases shared by the REST API and future non-CLI clients.

This module deliberately deals in repository payloads at its boundary. Domain decisions and
reconciliation remain in ``application`` and ``services``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
from typing import Any

from access_review_engine.application import import_file_to_repository, load_classification_rules
from access_review_engine.domain import Finding
from access_review_engine.storage import Repository


@dataclass(frozen=True)
class PreviewSyncResult:
    tables: dict[str, dict[str, int]]
    objects: dict[str, dict[str, int]]
    comparison: dict[str, int]
    collection_incomplete: bool
    persisted: bool = False

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def list_payloads(
    db_path: str | Path,
    table: str,
    *,
    limit: int = 100,
    offset: int = 0,
    search: str | None = None,
    status: str | None = None,
    provider: str | None = None,
) -> dict[str, object]:
    with Repository(db_path) as repo:
        rows = repo.list_payloads(table)
    filtered = [
        row for row in rows
        if (not search or search.lower() in json.dumps(row, sort_keys=True).lower())
        and (not status or row.get("status") == status)
        and (not provider or row.get("provider") == provider
             or row.get("identity_provider") == provider
             or row.get("access_provider") == provider)
    ]
    return {"items": filtered[offset : offset + limit], "total": len(filtered), "limit": limit, "offset": offset}


def latest_snapshot(db_path: str | Path) -> dict[str, Any] | None:
    with Repository(db_path) as repo:
        rows = repo.list_payloads("snapshots")
    return rows[-1] if rows else None


def preview_import(
    db_path: str | Path,
    input_path: str | Path,
    *,
    provider: str = "openldap",
    classification_rules: str | Path | None = None,
) -> PreviewSyncResult:
    """Run the real import engine against a SQLite backup and discard the backup."""
    source = Path(db_path)
    target_parent = Path(tempfile.mkdtemp(prefix="eare-preview-"))
    target = target_parent / "preview.db"
    before = table_counts(source)
    try:
        backup_if_present(source, target)
        repo = Repository(target)
        try:
            snapshot = import_file_to_repository(
                repo,
                input_path,
                provider_name=provider,
                classification_rules=load_classification_rules(classification_rules),
            )
        finally:
            repo.close()
        after = table_counts(target)
        changed = {
            table: {"before": before[table], "after": after[table]}
            for table in before
            if before[table] != after[table]
        }
        states: dict[str, int] = {}
        for row in snapshot.comparison_states:
            key = str(row.get("classification", "unknown"))
            states[key] = states.get(key, 0) + 1
        incomplete = any(
            Finding.COLLECTION_INCOMPLETE in row.get("findings", [])
            for row in snapshot.comparison_states
        )
        return PreviewSyncResult(
            tables=changed,
            objects=object_deltas(source, target),
            comparison=states,
            collection_incomplete=incomplete,
        )
    finally:
        shutil.rmtree(target_parent, ignore_errors=True)


def table_counts(path: str | Path) -> dict[str, int]:
    from access_review_engine.storage import TABLES

    counts = {table: 0 for table in TABLES}
    if not Path(path).exists():
        return counts
    connection = sqlite3.connect(path)
    try:
        for table in counts:
            counts[table] = int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
    finally:
        connection.close()
    return counts


def backup_if_present(source: str | Path, target: Path) -> None:
    if not Path(source).exists():
        return
    source_conn = sqlite3.connect(source)
    target_conn = sqlite3.connect(target)
    try:
        source_conn.backup(target_conn)
    finally:
        target_conn.close()
        source_conn.close()


def object_deltas(before_path: str | Path, after_path: str | Path) -> dict[str, dict[str, int]]:
    from access_review_engine.storage import TABLES

    def records(path: str | Path, table: str) -> dict[str, dict[str, Any]]:
        if not Path(path).exists():
            return {}
        connection = sqlite3.connect(path)
        try:
            rows = connection.execute(f"SELECT id, payload FROM {table}").fetchall()
            return {str(row[0]): json.loads(str(row[1])) for row in rows}
        finally:
            connection.close()

    result: dict[str, dict[str, int]] = {}
    for table in TABLES:
        before = records(before_path, table)
        after = records(after_path, table)
        common = set(before) & set(after)
        counts = {"added": len(set(after) - set(before)), "removed": len(set(before) - set(after)), "updated": 0, "renamed": 0, "disabled": 0, "deleted": 0}
        for object_id in common:
            old, new = before[object_id], after[object_id]
            if old == new:
                continue
            if payload_name(old) != payload_name(new):
                counts["renamed"] += 1
            if old.get("status") != "disabled" and new.get("status") == "disabled":
                counts["disabled"] += 1
            if old.get("status") != "deleted" and new.get("status") == "deleted":
                counts["deleted"] += 1
            counts["updated"] += 1
        if any(counts.values()):
            result[table] = counts
    return result


def payload_name(payload: dict[str, Any]) -> str | None:
    for key in ("name", "identifier", "access_name"):
        if payload.get(key) is not None:
            return str(payload[key])
    return None
