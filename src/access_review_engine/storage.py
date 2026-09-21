from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterator

from access_review_engine.domain import (
    SYSTEM_CAPABILITIES,
    Access,
    AccessAssignment,
    AccessRelation,
    AuditEvent,
    AuthenticationPosture,
    Campaign,
    Decision,
    GoldenSource,
    GoldenSourceVersion,
    Identity,
    IdentityStatus,
    ImportBatch,
    Provider,
    RemediationAction,
    Resource,
    ReviewItem,
    Snapshot,
)

TABLES = {
    "providers",
    "identities",
    "resources",
    "accesses",
    "access_assignments",
    "access_relations",
    "imports",
    "golden_sources",
    "golden_source_versions",
    "golden_source_assignments",
    "snapshots",
    "snapshot_identities",
    "snapshot_resources",
    "snapshot_accesses",
    "snapshot_assignments",
    "campaigns",
    "review_items",
    "decisions",
    "audit_events",
    "remediation_actions",
    "access_enrichments",
    "campaign_access_contexts",
    "golden_assignment_annotations",
    "capabilities",
    "permission_capability_mappings",
}


class Repository:
    """Small SQLite repository for the MVP.

    Rows are stored as canonical JSON payloads to keep the domain model independent while preserving
    explicit table boundaries expected by the later SQLAlchemy/Alembic implementation.
    """

    def __init__(self, path: str | Path = "access-review.db") -> None:
        self.path = str(path)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self._transaction_depth = 0
        self.init_schema()

    def __enter__(self) -> "Repository":
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> bool:
        self.close()
        return False

    def init_schema(self) -> None:
        cur = self.conn.cursor()
        for table in sorted(TABLES):
            cur.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {table} (
                    id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    created_at TEXT,
                    provider TEXT,
                    name TEXT,
                    version INTEGER
                )
                """
            )
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_providers_name ON providers(name)")
        cur.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_identity_ref "
            "ON identities(provider, name)"
        )
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_access_ref ON accesses(provider, name)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_assignments_access ON access_assignments(provider, name)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_assignments_identity ON access_assignments(provider)")
        cur.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_access_relation_ref "
            "ON access_relations(provider, name)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS ix_access_relations_parent "
            "ON access_relations(provider, name)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS ix_access_relations_child "
            "ON access_relations("
            "json_extract(payload, '$.child_provider'), "
            "json_extract(payload, '$.child_access_name'))"
        )
        cur.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_golden_source_name ON golden_sources(name)"
        )
        cur.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_golden_version "
            "ON golden_source_versions(name, version)"
        )
        for capability in SYSTEM_CAPABILITIES:
            payload = json.dumps(asdict(capability), sort_keys=True, separators=(",", ":"))
            cur.execute(
                "INSERT OR IGNORE INTO capabilities (id, payload, name) VALUES (?, ?, ?)",
                (capability.id, payload, capability.id),
            )
        self.conn.commit()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        outermost = self._transaction_depth == 0
        if outermost:
            self.conn.execute("BEGIN")
        self._transaction_depth += 1
        try:
            yield
        except Exception:
            if outermost:
                self.conn.rollback()
            raise
        else:
            if outermost:
                self.conn.commit()
        finally:
            self._transaction_depth -= 1

    def _commit_unless_in_transaction(self) -> None:
        if self._transaction_depth == 0:
            self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def upsert(self, table: str, obj: Any) -> None:
        payload = self._payload(obj)
        self.conn.execute(
            f"""
            INSERT INTO {table} (id, payload, created_at, provider, name, version)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              payload=excluded.payload,
              created_at=excluded.created_at,
              provider=excluded.provider,
              name=excluded.name,
              version=excluded.version
            """,
            self._row(obj, payload),
        )
        self._commit_unless_in_transaction()

    def insert_append_only(self, table: str, obj: Any) -> None:
        payload = self._payload(obj)
        self.conn.execute(
            f"INSERT INTO {table} (id, payload, created_at, provider, name, version) VALUES (?, ?, ?, ?, ?, ?)",
            self._row(obj, payload),
        )
        self._commit_unless_in_transaction()

    def delete_ids(self, table: str, object_ids: set[str]) -> None:
        for object_id in object_ids:
            self.conn.execute(f"DELETE FROM {table} WHERE id = ?", (object_id,))
        self._commit_unless_in_transaction()

    def list_payloads(self, table: str) -> list[dict[str, Any]]:
        return [
            json.loads(row["payload"])
            for row in self.conn.execute(f"SELECT payload FROM {table} ORDER BY created_at, id")
        ]

    def list_payloads_by_provider(self, table: str, provider: str) -> list[dict[str, Any]]:
        return [
            json.loads(row["payload"])
            for row in self.conn.execute(
                f"SELECT payload FROM {table} WHERE provider = ? ORDER BY created_at, id",
                (provider,),
            )
        ]

    def get_payload(self, table: str, object_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(f"SELECT payload FROM {table} WHERE id = ?", (object_id,)).fetchone()
        return None if row is None else json.loads(row["payload"])

    def find_by_name(self, table: str, name: str) -> dict[str, Any] | None:
        row = self.conn.execute(f"SELECT payload FROM {table} WHERE name = ?", (name,)).fetchone()
        return None if row is None else json.loads(row["payload"])

    def find_by_provider_name(self, table: str, provider: str, name: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            f"SELECT payload FROM {table} WHERE provider = ? AND name = ?",
            (provider, name),
        ).fetchone()
        return None if row is None else json.loads(row["payload"])

    def find_version(self, golden_source_id: str, version: int) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT payload FROM golden_source_versions WHERE name = ? AND version = ?",
            (golden_source_id, version),
        ).fetchone()
        return None if row is None else json.loads(row["payload"])

    def save_capability(self, capability: Any) -> None:
        from dataclasses import asdict

        existing = self.get_payload("capabilities", capability.id)
        if existing is not None and bool(existing.get("system")) != bool(capability.system):
            raise ValueError("Capability system/custom classification is immutable")
        self.upsert("capabilities", asdict(capability) | {"name": capability.id})

    def list_capabilities(self) -> list[Any]:
        from access_review_engine.domain import Capability

        return [
            Capability(**{key: value for key, value in row.items() if key != "name"})
            for row in self.list_payloads("capabilities")
        ]

    def delete_capability(self, capability_id: str) -> None:
        for mapping in self.list_payloads("permission_capability_mappings"):
            if capability_id in mapping.get("capability_ids", []):
                raise ValueError("A used Capability cannot be deleted; deactivate it instead")
        for version in self.list_payloads("golden_source_versions"):
            for model in version.get("functional_access_models", []):
                if any(
                    right.get("capability_id") == capability_id for right in model.get("rights", [])
                ):
                    raise ValueError("A Capability referenced by Golden history cannot be deleted")
        capability = self.get_payload("capabilities", capability_id)
        if capability and capability.get("system"):
            raise ValueError("System Capabilities cannot be deleted")
        self.delete_ids("capabilities", {capability_id})

    def save_permission_capability_mapping(self, mapping: Any) -> None:
        from dataclasses import asdict

        from access_review_engine.domain import stable_checksum

        known = {item.id for item in self.list_capabilities()}
        if not set(mapping.capability_ids) <= known:
            raise ValueError("Permission mapping references an unknown Capability")
        payload = asdict(mapping)
        mapping_id = stable_checksum(
            {
                "provider": mapping.provider,
                "permission_identifier": mapping.permission_identifier,
            }
        )
        self.upsert("permission_capability_mappings", payload | {"id": mapping_id})

    def list_permission_capability_mappings(self) -> list[Any]:
        from access_review_engine.domain import PermissionCapabilityMapping

        return [
            PermissionCapabilityMapping(
                **(
                    {key: value for key, value in row.items() if key != "id"}
                    | {"capability_ids": tuple(row["capability_ids"])}
                )
            )
            for row in self.list_payloads("permission_capability_mappings")
        ]

    def replace_assignments(
        self, assignments: list[AccessAssignment], providers: set[str] | None = None
    ) -> None:
        scoped_providers = providers or {assignment.provider for assignment in assignments}
        if not scoped_providers:
            return
        for provider in scoped_providers:
            self.conn.execute("DELETE FROM access_assignments WHERE provider = ?", (provider,))
        for assignment in assignments:
            self.conn.execute(
                "INSERT INTO access_assignments (id, payload, created_at, provider, name, version) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                self._row(assignment, self._payload(assignment)),
            )
        self._commit_unless_in_transaction()

    def replace_access_relations(
        self, relations: list[AccessRelation], providers: set[str] | None = None
    ) -> None:
        scoped_providers = providers or {relation.parent_provider for relation in relations}
        if not scoped_providers:
            return
        seen: set[tuple[str, str, str, str, str, str]] = set()
        for provider in scoped_providers:
            self.conn.execute("DELETE FROM access_relations WHERE provider = ?", (provider,))
        for relation in relations:
            if relation.key() in seen:
                continue
            seen.add(relation.key())
            self.conn.execute(
                "INSERT INTO access_relations (id, payload, created_at, provider, name, version) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                self._row(relation, self._payload(relation)),
            )
        self._commit_unless_in_transaction()

    def _payload(self, obj: Any) -> str:
        if isinstance(obj, dict):
            data = obj
        else:
            data = asdict(obj)
        return json.dumps(data, sort_keys=True, separators=(",", ":"))

    def _row(self, obj: Any, payload: str) -> tuple[Any, ...]:
        data = json.loads(payload)
        provider = data.get("provider") or data.get("access_provider") or data.get("identity_provider")
        name = data.get("name") or data.get("identifier") or data.get("golden_source_id")
        if isinstance(obj, Identity) and data.get("status") == IdentityStatus.DELETED:
            name = f"{name}#deleted:{data.get('native_id') or data['id']}"
        if isinstance(obj, GoldenSourceVersion):
            name = obj.golden_source_id
        if isinstance(obj, AccessAssignment):
            name = obj.access_name
        if isinstance(obj, AccessRelation):
            provider = obj.parent_provider
            name = ":".join(obj.key())
        return (
            data["id"],
            payload,
            data.get("created_at"),
            provider,
            name,
            data.get("version"),
        )


def hydrate_provider(data: dict[str, Any]) -> Provider:
    return Provider(**data)


def hydrate_identity(data: dict[str, Any]) -> Identity:
    from access_review_engine.domain import OwnerRef

    owner = data.get("account_owner")
    return Identity(**(data | {"account_owner": OwnerRef(**owner) if owner else None}))


def hydrate_resource(data: dict[str, Any]) -> Resource:
    return Resource(**data)


def hydrate_access(data: dict[str, Any]) -> Access:
    from access_review_engine.domain import ControlObject, OwnerRef, Permission, Target

    owner = data.get("access_owner")
    return Access(
        **(data | {
            "control_object": ControlObject(**data["control_object"])
            if data.get("control_object")
            else None,
            "permission": Permission(**data["permission"]) if data.get("permission") else None,
            "target": Target(**data["target"]) if data.get("target") else None,
            "access_owner": OwnerRef(**owner) if owner else None,
        })
    )


def hydrate_assignment(data: dict[str, Any]) -> AccessAssignment:
    from access_review_engine.domain import Origin

    return AccessAssignment(**(data | {"origin": Origin(**data["origin"])}))


def hydrate_access_relation(data: dict[str, Any]) -> AccessRelation:
    from access_review_engine.domain import Origin

    return AccessRelation(**(data | {"origin": Origin(**data["origin"])}))


def hydrate_authentication_posture(data: dict[str, Any] | None) -> AuthenticationPosture | None:
    if not data:
        return None
    return AuthenticationPosture(**data)


def hydrate_snapshot(data: dict[str, Any]) -> Snapshot:
    return Snapshot(
        providers=[hydrate_provider(item) for item in data["providers"]],
        identities=[hydrate_identity(item) for item in data["identities"]],
        resources=[hydrate_resource(item) for item in data["resources"]],
        accesses=[hydrate_access(item) for item in data["accesses"]],
        access_assignments=[hydrate_assignment(item) for item in data["access_assignments"]],
        source_import_ids=data["source_import_ids"],
        access_relations=[
            hydrate_access_relation(item) for item in data.get("access_relations", [])
        ],
        comparison_states=data.get("comparison_states", []),
        authentication_posture=hydrate_authentication_posture(data.get("authentication_posture")),
        id=data["id"],
        created_at=data["created_at"],
        immutable=data.get("immutable", True),
        checksum=data["checksum"],
    )


def hydrate_golden_source(data: dict[str, Any]) -> GoldenSource:
    return GoldenSource(**data)


def hydrate_golden_version(data: dict[str, Any]) -> GoldenSourceVersion:
    from access_review_engine.domain import (
        ExpectedAccessModel,
        FunctionalRight,
        GoldenAccessComment,
        GoldenSourceAssignment,
        Target,
    )

    models = []
    for item in data.get("functional_access_models", []):
        rights = tuple(
            FunctionalRight(
                target=Target(**right["target"]),
                capability_id=right["capability_id"],
                provenance=right.get("provenance", "manual"),
                native_permission=right.get("native_permission"),
            )
            for right in item.get("rights", [])
        )
        models.append(
            ExpectedAccessModel(
                access_provider=item["access_provider"],
                access_name=item["access_name"],
                completeness=item.get("completeness", "not_defined"),
                rights=rights,
            )
        )
    return GoldenSourceVersion(
        **(
            data
            | {
                "assignments": [GoldenSourceAssignment(**item) for item in data["assignments"]],
                "golden_authentication_policy": hydrate_authentication_posture(
                    data.get("golden_authentication_policy")
                ),
                "schema_version": data.get("schema_version", 1),
                "expected_access_definitions": [
                    hydrate_access(item) for item in data.get("expected_access_definitions", [])
                ],
                "expected_access_relations": [
                    hydrate_access_relation(item)
                    for item in data.get("expected_access_relations", [])
                ],
                "functional_access_models": models,
                "access_comments": [
                    GoldenAccessComment(**item) for item in data.get("access_comments", [])
                ],
            }
        )
    )


def hydrate_campaign(data: dict[str, Any]) -> Campaign:
    from access_review_engine.domain import OwnerRef

    return Campaign(
        **(
            data
            | {
                "default_reviewer": OwnerRef(**data["default_reviewer"])
                if data.get("default_reviewer")
                else None,
                "manager": OwnerRef(**data["manager"]) if data.get("manager") else None,
            }
        )
    )


def hydrate_review_item(data: dict[str, Any]) -> ReviewItem:
    from access_review_engine.domain import OwnerRef

    return ReviewItem(
        **(
            data
            | {
                "account_owner": OwnerRef(**data["account_owner"]) if data.get("account_owner") else None,
                "access_owner": OwnerRef(**data["access_owner"]) if data.get("access_owner") else None,
                "reviewer": OwnerRef(**data["reviewer"]) if data.get("reviewer") else None,
            }
        )
    )


def hydrate_decision(data: dict[str, Any]) -> Decision:
    return Decision(**data)


def hydrate_import(data: dict[str, Any]) -> ImportBatch:
    return ImportBatch(**data)


def hydrate_remediation(data: dict[str, Any]) -> RemediationAction:
    return RemediationAction(**data)


def hydrate_audit(data: dict[str, Any]) -> AuditEvent:
    return AuditEvent(**data)
