from __future__ import annotations

import copy
import sqlite3

import pytest

from access_review_engine.domain import (
    Access,
    AccessRelation,
    AccessRelationType,
    ControlObject,
    Origin,
    Permission,
    Snapshot,
)
from access_review_engine.services import create_snapshot
from access_review_engine.storage import Repository, hydrate_snapshot


def test_repository_persists_access_relation_with_relation_indexes(tmp_path) -> None:
    repo = Repository(tmp_path / "relations.db")
    try:
        parent = _access("role")
        child = _access("customers:read", permission="read")
        relation = _relation("role", "customers:read")
        repo.upsert("accesses", parent)
        repo.upsert("accesses", child)
        repo.replace_access_relations([relation, copy.deepcopy(relation)], providers={"app"})

        rows = repo.list_payloads("access_relations")
        assert len(rows) == 1
        assert rows[0]["parent_access_name"] == "role"
        assert rows[0]["child_access_name"] == "customers:read"
        index_names = {row[1] for row in repo.conn.execute("PRAGMA index_list(access_relations)")}
        assert "uq_access_relation_ref" in index_names
        assert "ix_access_relations_parent" in index_names
        assert "ix_access_relations_child" in index_names
    finally:
        repo.close()


def test_duplicate_access_relation_upsert_is_rejected_by_sqlite_unique_key(tmp_path) -> None:
    repo = Repository(tmp_path / "relations.db")
    try:
        relation = _relation("role", "customers:read")
        duplicate = copy.deepcopy(relation)
        duplicate.id = "different-id"
        repo.upsert("access_relations", relation)
        with pytest.raises(sqlite3.IntegrityError):
            repo.upsert("access_relations", duplicate)
    finally:
        repo.close()


def test_legacy_snapshot_without_access_relations_hydrates_with_empty_list() -> None:
    snapshot = create_snapshot([], [], [], [], [], ["import-1"])
    payload = copy.deepcopy(snapshot.__dict__)
    payload.pop("access_relations")

    restored = hydrate_snapshot(payload)

    assert isinstance(restored, Snapshot)
    assert restored.access_relations == []


def _relation(parent: str, child: str) -> AccessRelation:
    return AccessRelation(
        parent_provider="app",
        parent_access_name=parent,
        child_provider="app",
        child_access_name=child,
        relation_type=AccessRelationType.GRANTS,
        origin=Origin("relation", False, True, "test"),
    )


def _access(name: str, permission: str = "use") -> Access:
    return Access(name, "app", ControlObject("role", name), Permission(permission))
