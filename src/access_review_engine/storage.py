from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any, Literal

from sqlalchemy import Column, Index, Integer, MetaData, Table, Text, delete, insert, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from access_review_engine.database import (
    DatabaseConnection,
    database_url,
    make_engine,
    safe_identifier,
)
from access_review_engine.domain import (
    SYSTEM_CAPABILITIES,
    Access,
    AccessAssignment,
    AccessRelation,
    AuditEvent,
    AuthenticationPosture,
    Campaign,
    Decision,
    ExpectedAccessModel,
    FunctionalRight,
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
    Target,
    now_utc,
    stable_checksum,
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
    "snapshot_functional_access_models",
    "campaigns",
    "review_items",
    "decisions",
    "audit_events",
    "remediation_actions",
    "finding_tracking",
    "access_enrichments",
    "campaign_access_contexts",
    "golden_assignment_annotations",
    "business_context_feedback",
    "capabilities",
    "permission_capability_mappings",
    "golden_applications",
    "chatbot_conversations",
    "chatbot_messages",
    "chatbot_traces",
    "organizations",
    "information_systems",
    "organization_information_systems",
    "scope_assignments",
}


def repository_metadata() -> tuple[MetaData, dict[str, Table]]:
    """Describe only the existing persistence tables; domain payloads stay opaque TEXT."""
    metadata = MetaData()
    tables = {
        name: Table(
            name,
            metadata,
            Column("id", Text, primary_key=True),
            Column("payload", Text, nullable=False),
            Column("created_at", Text),
            Column("provider", Text),
            Column("name", Text),
            Column("version", Integer),
        )
        for name in TABLES
    }
    Index("uq_providers_name", tables["providers"].c.name, unique=True)
    Index(
        "uq_identity_ref", tables["identities"].c.provider, tables["identities"].c.name, unique=True
    )
    Index("uq_access_ref", tables["accesses"].c.provider, tables["accesses"].c.name, unique=True)
    Index(
        "ix_assignments_access",
        tables["access_assignments"].c.provider,
        tables["access_assignments"].c.name,
    )
    Index("ix_assignments_identity", tables["access_assignments"].c.provider)
    Index(
        "uq_access_relation_ref",
        tables["access_relations"].c.provider,
        tables["access_relations"].c.name,
        unique=True,
    )
    Index(
        "ix_access_relations_parent",
        tables["access_relations"].c.provider,
        tables["access_relations"].c.name,
    )
    Index("uq_golden_source_name", tables["golden_sources"].c.name, unique=True)
    Index(
        "uq_golden_version",
        tables["golden_source_versions"].c.name,
        tables["golden_source_versions"].c.version,
        unique=True,
    )
    return metadata, tables


def create_repository_schema(connection: Any) -> dict[str, Table]:
    """Create the current schema and dialect-specific expression indexes."""
    metadata, tables = repository_metadata()
    metadata.create_all(connection)
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_snapshot_functional_models_snapshot "
            "ON snapshot_functional_access_models ((payload::json ->> 'snapshot_id'))"
        )
        connection.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_access_relations_child "
            "ON access_relations ((payload::json ->> 'child_provider'), "
            "(payload::json ->> 'child_access_name'))"
        )
    else:
        connection.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_snapshot_functional_models_snapshot "
            "ON snapshot_functional_access_models(json_extract(payload, '$.snapshot_id'))"
        )
        connection.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_access_relations_child "
            "ON access_relations(json_extract(payload, '$.child_provider'), "
            "json_extract(payload, '$.child_access_name'))"
        )
    return tables


class Repository:
    """Synchronous SQLAlchemy Core repository backed by SQLite or PostgreSQL.

    Rows are stored as canonical JSON payloads to keep the domain model independent while preserving
    explicit table boundaries expected by the later SQLAlchemy/Alembic implementation.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self.engine = make_engine(database_url(path))
        self.path = self.engine.url.render_as_string(hide_password=True)
        self.conn = DatabaseConnection(self.engine.connect())
        self._tables: dict[str, Table] = {}
        self._transaction_depth = 0
        self.init_schema()

    def __enter__(self) -> Repository:
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> Literal[False]:
        self.close()
        return False

    def init_schema(self) -> None:
        tables = create_repository_schema(self.conn.raw)
        self._tables = tables
        for capability in SYSTEM_CAPABILITIES:
            payload = json.dumps(asdict(capability), sort_keys=True, separators=(",", ":"))
            statement = (pg_insert if self.conn.dialect_name == "postgresql" else sqlite_insert)(
                tables["capabilities"]
            )
            self.conn.raw.execute(
                statement.values(
                    id=capability.id, payload=payload, name=capability.id
                ).on_conflict_do_nothing(index_elements=[tables["capabilities"].c.id])
            )
        self.conn.commit()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        outermost = self._transaction_depth == 0
        # SQLAlchemy autobegins a transaction even for SELECTs; the legacy sqlite3
        # connection did not. Finish that read-only unit before the explicit scope.
        if outermost and self.conn.raw.in_transaction():
            self.conn.commit()
        transaction = self.conn.raw.begin() if outermost else None
        self._transaction_depth += 1
        try:
            yield
        except Exception:
            if outermost:
                assert transaction is not None
                if transaction.is_active:
                    transaction.rollback()
            raise
        else:
            if outermost:
                assert transaction is not None
                if transaction.is_active:
                    transaction.commit()
        finally:
            self._transaction_depth -= 1

    def _commit_unless_in_transaction(self) -> None:
        if self._transaction_depth == 0:
            self.conn.commit()

    def close(self) -> None:
        self.conn.close()
        self.engine.dispose()

    def _table(self, name: str) -> Table:
        return self._tables[safe_identifier(name, TABLES)]

    def upsert(self, table: str, obj: Any) -> None:
        table_object = self._table(table)
        payload = self._payload(obj)
        dialect_insert = pg_insert if self.conn.dialect_name == "postgresql" else sqlite_insert
        statement = dialect_insert(table_object).values(**self._row(obj, payload))
        self.conn.execute(
            statement.on_conflict_do_update(
                index_elements=[table_object.c.id],
                set_={
                    column: getattr(statement.excluded, column)
                    for column in ("payload", "created_at", "provider", "name", "version")
                },
            )
        )
        self._commit_unless_in_transaction()

    def insert_append_only(self, table: str, obj: Any) -> None:
        table_object = self._table(table)
        payload = self._payload(obj)
        self.conn.execute(insert(table_object).values(**self._row(obj, payload)))
        self._commit_unless_in_transaction()

    def delete_ids(self, table: str, object_ids: set[str]) -> None:
        table_object = self._table(table)
        if object_ids:
            self.conn.execute(delete(table_object).where(table_object.c.id.in_(object_ids)))
        self._commit_unless_in_transaction()

    def list_payloads(self, table: str) -> list[dict[str, Any]]:
        table_object = self._table(table)
        return [
            json.loads(row["payload"])
            for row in self.conn.execute(
                select(table_object.c.payload).order_by(
                    table_object.c.created_at.asc().nulls_first(), table_object.c.id
                )
            )
        ]

    def list_payloads_by_provider(self, table: str, provider: str) -> list[dict[str, Any]]:
        table_object = self._table(table)
        return [
            json.loads(row["payload"])
            for row in self.conn.execute(
                select(table_object.c.payload)
                .where(table_object.c.provider == provider)
                .order_by(table_object.c.created_at.asc().nulls_first(), table_object.c.id)
            )
        ]

    def get_payload(self, table: str, object_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            select(self._table(table).c.payload).where(self._table(table).c.id == object_id)
        ).fetchone()
        return None if row is None else json.loads(row["payload"])

    def save_snapshot_functional_models(
        self,
        snapshot_id: str,
        source_import_id: str,
        models: list[ExpectedAccessModel],
        *,
        authoritative: bool,
        evidence: dict[str, Any] | None = None,
    ) -> None:
        """Append observed models with their snapshot in the caller's transaction."""
        for model in models:
            self.insert_append_only(
                "snapshot_functional_access_models",
                {
                    "id": stable_checksum((snapshot_id, model.access_provider, model.access_name)),
                    "snapshot_id": snapshot_id,
                    "source_import_id": source_import_id,
                    "access_provider": model.access_provider,
                    "access_name": model.access_name,
                    "completeness": model.completeness,
                    "rights": [asdict(right) for right in model.rights],
                    "authoritative": authoritative,
                    "evidence": evidence or {},
                    "created_at": now_utc(),
                },
            )

    def load_snapshot_functional_models(self, snapshot_id: str) -> list[dict[str, Any]]:
        """Read only the immutable models attached to one snapshot."""
        if self.conn.dialect_name == "postgresql":
            query = text(
                "SELECT payload FROM snapshot_functional_access_models "
                "WHERE payload::json ->> 'snapshot_id' = :snapshot_id "
                "ORDER BY provider NULLS FIRST, id"
            )
        else:
            query = text(
                "SELECT payload FROM snapshot_functional_access_models "
                "WHERE json_extract(payload, '$.snapshot_id') = :snapshot_id "
                "ORDER BY provider NULLS FIRST, id"
            )
        return [
            json.loads(row["payload"])
            for row in self.conn.execute(
                query,
                {"snapshot_id": snapshot_id},
            )
        ]

    def find_by_name(self, table: str, name: str) -> dict[str, Any] | None:
        table_object = self._table(table)
        row = self.conn.execute(
            select(table_object.c.payload).where(table_object.c.name == name)
        ).fetchone()
        return None if row is None else json.loads(row["payload"])

    def find_by_provider_name(self, table: str, provider: str, name: str) -> dict[str, Any] | None:
        table_object = self._table(table)
        row = self.conn.execute(
            select(table_object.c.payload).where(
                table_object.c.provider == provider, table_object.c.name == name
            )
        ).fetchone()
        return None if row is None else json.loads(row["payload"])

    def find_version(self, golden_source_id: str, version: int) -> dict[str, Any] | None:
        table = self._tables["golden_source_versions"]
        row = self.conn.execute(
            select(table.c.payload).where(
                table.c.name == golden_source_id, table.c.version == version
            )
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
        table = self._tables["access_assignments"]
        for provider in scoped_providers:
            self.conn.execute(delete(table).where(table.c.provider == provider))
        for assignment in assignments:
            self.conn.execute(
                insert(table).values(**self._row(assignment, self._payload(assignment)))
            )
        self._commit_unless_in_transaction()

    def replace_access_relations(
        self, relations: list[AccessRelation], providers: set[str] | None = None
    ) -> None:
        scoped_providers = providers or {relation.parent_provider for relation in relations}
        if not scoped_providers:
            return
        table = self._tables["access_relations"]
        seen: set[tuple[str, str, str, str, str, str]] = set()
        for provider in scoped_providers:
            self.conn.execute(delete(table).where(table.c.provider == provider))
        for relation in relations:
            if relation.key() in seen:
                continue
            seen.add(relation.key())
            self.conn.execute(insert(table).values(**self._row(relation, self._payload(relation))))
        self._commit_unless_in_transaction()

    def _payload(self, obj: Any) -> str:
        if isinstance(obj, dict):
            data = obj
        else:
            data = asdict(obj)
        return json.dumps(data, sort_keys=True, separators=(",", ":"))

    def _row(self, obj: Any, payload: str) -> dict[str, Any]:
        data = json.loads(payload)
        provider = (
            data.get("provider") or data.get("access_provider") or data.get("identity_provider")
        )
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
        return {
            "id": data["id"],
            "payload": payload,
            "created_at": data.get("created_at"),
            "provider": provider,
            "name": name,
            "version": data.get("version"),
        }


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
        **(
            data
            | {
                "control_object": ControlObject(**data["control_object"])
                if data.get("control_object")
                else None,
                "permission": Permission(**data["permission"]) if data.get("permission") else None,
                "target": Target(**data["target"]) if data.get("target") else None,
                "access_owner": OwnerRef(**owner) if owner else None,
            }
        )
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


def hydrate_functional_model(data: dict[str, Any]) -> ExpectedAccessModel:
    return ExpectedAccessModel(
        access_provider=str(data["access_provider"]),
        access_name=str(data["access_name"]),
        completeness=str(data["completeness"]),
        rights=tuple(
            FunctionalRight(
                target=Target(**right["target"]),
                capability_id=str(right["capability_id"]),
                provenance=str(right.get("provenance", "mapped")),
                native_permission=right.get("native_permission"),
            )
            for right in data.get("rights", [])
        ),
    )


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
                "account_owner": OwnerRef(**data["account_owner"])
                if data.get("account_owner")
                else None,
                "access_owner": OwnerRef(**data["access_owner"])
                if data.get("access_owner")
                else None,
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
