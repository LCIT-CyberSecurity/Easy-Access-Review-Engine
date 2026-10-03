"""Organization and information-system perimeter operations.

Perimeters are classification data. They deliberately remain separate from Access,
Target, Permission, Capability and FunctionalRight identity semantics.
"""

from __future__ import annotations

from typing import Any

from access_review_engine.domain import new_id, now_utc


ENTITY_TABLES = {"organization": "organizations", "information_system": "information_systems"}


def _clean_name(value: Any) -> str:
    name = str(value or "").strip()
    if not name or len(name) > 200:
        raise ValueError("Perimeter name must contain 1 to 200 characters")
    return name


def _all(repo: Any, kind: str) -> list[dict[str, Any]]:
    return repo.list_payloads(ENTITY_TABLES[kind])


def _get(repo: Any, kind: str, identifier: str) -> dict[str, Any]:
    row = repo.get_payload(ENTITY_TABLES[kind], identifier)
    if row is None:
        raise ValueError(f"{kind.replace('_', ' ').capitalize()} not found")
    return row


def _assert_parent(repo: Any, kind: str, identifier: str, parent_id: str | None) -> None:
    if parent_id is None:
        return
    if identifier == parent_id:
        raise ValueError("A perimeter cannot be its own parent")
    current = parent_id
    visited: set[str] = set()
    while current:
        if current in visited:
            raise ValueError("Perimeter hierarchy contains a cycle")
        visited.add(current)
        parent = _get(repo, kind, current)
        current = str(parent.get("parent_id") or "") or None
        if current == identifier:
            raise ValueError("Perimeter hierarchy cannot contain a cycle")


def create_perimeter(repo: Any, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
    name = _clean_name(payload.get("name"))
    parent_id = str(payload.get("parent_id") or "") or None
    identifier = new_id()
    if parent_id:
        _get(repo, kind, parent_id)
    _assert_parent(repo, kind, identifier, parent_id)
    now = now_utc()
    row = {
        "id": identifier,
        "name": name,
        "parent_id": parent_id,
        "description": str(payload.get("description") or "").strip() or None,
        "active": bool(payload.get("active", True)),
        "created_at": now,
        "updated_at": now,
    }
    repo.upsert(ENTITY_TABLES[kind], row)
    return row


def update_perimeter(repo: Any, kind: str, identifier: str, payload: dict[str, Any]) -> dict[str, Any]:
    current = _get(repo, kind, identifier)
    parent_id = str(payload.get("parent_id") or "") or None if "parent_id" in payload else current.get("parent_id")
    if parent_id:
        _get(repo, kind, parent_id)
    _assert_parent(repo, kind, identifier, parent_id)
    row = {
        **current,
        "name": _clean_name(payload.get("name", current.get("name"))),
        "parent_id": parent_id,
        "description": str(payload.get("description", current.get("description")) or "").strip() or None,
        "active": bool(payload.get("active", current.get("active", True))),
        "updated_at": now_utc(),
    }
    repo.upsert(ENTITY_TABLES[kind], row)
    return row


def descendants(repo: Any, kind: str, identifier: str) -> list[dict[str, Any]]:
    _get(repo, kind, identifier)
    rows = _all(repo, kind)
    result: list[dict[str, Any]] = []
    pending = [identifier]
    while pending:
        parent = pending.pop(0)
        children = [row for row in rows if row.get("parent_id") == parent]
        result.extend(children)
        pending.extend(str(row["id"]) for row in children)
    return result


def path(repo: Any, kind: str, identifier: str) -> list[dict[str, Any]]:
    current = _get(repo, kind, identifier)
    result = [current]
    seen = {identifier}
    while current.get("parent_id"):
        parent_id = str(current["parent_id"])
        if parent_id in seen:
            raise ValueError("Perimeter hierarchy contains a cycle")
        seen.add(parent_id)
        current = _get(repo, kind, parent_id)
        result.append(current)
    return list(reversed(result))


def associations(repo: Any) -> list[dict[str, Any]]:
    return repo.list_payloads("organization_information_systems")


def associate(repo: Any, organization_id: str, information_system_id: str) -> dict[str, Any]:
    _get(repo, "organization", organization_id)
    _get(repo, "information_system", information_system_id)
    for row in associations(repo):
        if row.get("organization_id") == organization_id and row.get("information_system_id") == information_system_id:
            return row
    row = {"id": new_id(), "organization_id": organization_id, "information_system_id": information_system_id, "created_at": now_utc()}
    repo.upsert("organization_information_systems", row)
    return row


def unassociate(repo: Any, organization_id: str, information_system_id: str) -> bool:
    for row in associations(repo):
        if row.get("organization_id") == organization_id and row.get("information_system_id") == information_system_id:
            repo.delete_ids("organization_information_systems", {str(row["id"])})
            return True
    return False


def object_assignments(repo: Any, object_type: str, object_id: str) -> list[dict[str, Any]]:
    return [row for row in repo.list_payloads("scope_assignments") if row.get("object_type") == object_type and row.get("object_id") == object_id]


def assign(repo: Any, payload: dict[str, Any]) -> dict[str, Any]:
    scope_type = str(payload.get("scope_type") or "").strip()
    scope_id = str(payload.get("scope_id") or "").strip()
    object_type = str(payload.get("object_type") or "").strip()
    object_id = str(payload.get("object_id") or "").strip()
    if scope_type not in ENTITY_TABLES or not scope_id or object_type not in {"access", "target", "identity"} or not object_id:
        raise ValueError("scope_type, scope_id, object_type and object_id are required")
    _get(repo, scope_type, scope_id)
    for row in object_assignments(repo, object_type, object_id):
        if row.get("scope_type") == scope_type and row.get("scope_id") == scope_id:
            return row
    row = {"id": new_id(), "scope_type": scope_type, "scope_id": scope_id, "object_type": object_type, "object_id": object_id, "created_at": now_utc()}
    repo.upsert("scope_assignments", row)
    return row
