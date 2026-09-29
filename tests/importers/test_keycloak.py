from __future__ import annotations

import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import yaml

import pytest
from access_review_engine.application import import_file_to_repository
from access_review_engine.importers.keycloak import import_keycloak_zip
from access_review_engine.services import calculate_effective_accesses
from access_review_engine.storage import Repository

FIXTURE = Path(__file__).parents[1] / "fixtures" / "keycloak"


def _artifact(tmp_path: Path) -> Path:
    output = tmp_path / "keycloak.zip"
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        for path in sorted(FIXTURE.iterdir()):
            archive.writestr(path.name, path.read_bytes())
    return output


def _custom_artifact(
    tmp_path: Path,
    *,
    manifest_changes: dict | None = None,
    omitted: set[str] | None = None,
    row_changes: dict[str, list[dict]] | None = None,
) -> Path:
    manifest = yaml.safe_load((FIXTURE / "manifest.yaml").read_text())
    manifest.update(manifest_changes or {})
    rows = {}
    for path in FIXTURE.iterdir():
        if path.name in {"manifest.yaml", "collection-errors.json"}:
            continue
        rows[path.name] = [json.loads(line) for line in path.read_text().splitlines() if line]
    rows.update(row_changes or {})
    counts = {
        surface: len(rows[filename])
        for surface, filename in {
            "users": "users.jsonl",
            "groups": "groups.jsonl",
            "memberships": "group-memberships.jsonl",
            "clients": "clients.jsonl",
            "realm_roles": "realm-roles.jsonl",
            "client_roles": "client-roles.jsonl",
            "user_role_mappings": "user-role-mappings.jsonl",
            "group_role_mappings": "group-role-mappings.jsonl",
            "composite_roles": "composite-role-relations.jsonl",
            "service_accounts": "service-accounts.jsonl",
        }.items()
        if filename in rows
    }
    manifest["counts"] = counts
    output = tmp_path / "custom-keycloak.zip"
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        archive.writestr("manifest.yaml", yaml.safe_dump(manifest, sort_keys=False))
        for path in sorted(FIXTURE.iterdir()):
            if path.name in (omitted or set()) or path.name == "manifest.yaml":
                continue
            if path.name == "collection-errors.json":
                archive.writestr(path.name, path.read_bytes())
            else:
                archive.writestr(
                    path.name,
                    "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows[path.name]),
                )
    return output


def test_keycloak_v0_normalizes_objects_and_preserves_native_ids(tmp_path: Path) -> None:
    result = import_keycloak_zip(_artifact(tmp_path))

    assert result.provider.type == "keycloak"
    assert result.batch.completeness == "full"
    assert {item.native_id for item in result.identities} >= {"u-alice", "g-finance", "u-backup"}
    assert (
        next(item for item in result.identities if item.native_id == "u-backup").type
        == "technical_account"
    )
    assert (
        next(item for item in result.identities if item.native_id == "u-charlie").status
        == "disabled"
    )
    assert {item.control_object.native_id for item in result.accesses if item.control_object} >= {
        "rr-accountant",
        "cr-crm-admin",
        "cr-erp-admin",
    }
    assert (
        len(
            [
                item
                for item in result.accesses
                if item.control_object
                and item.control_object.native_id in {"cr-crm-admin", "cr-erp-admin"}
            ]
        )
        == 2
    )


def test_keycloak_v0_effective_access_keeps_direct_and_inherited_paths(tmp_path: Path) -> None:
    result = import_keycloak_zip(_artifact(tmp_path))
    evaluation = calculate_effective_accesses(
        result.assignments, result.access_relations, result.accesses
    )

    bob = [item for item in evaluation.effective_accesses if item.identity_identifier == "bob"]
    accountant = next(item for item in bob if item.access_name.endswith("rr-accountant"))
    assert accountant.direct is False
    assert len(accountant.paths) >= 1
    assert any(path.relation_ids for path in accountant.paths)
    assert any(not item.direct for item in bob if item.access_name.endswith("rr-invoice-read"))

    alice = [item for item in evaluation.effective_accesses if item.identity_identifier == "alice"]
    assert any(item.access_name == "client:c-crm:role:cr-sales" and item.direct for item in alice)
    assert any(item.access_name.endswith("rr-accountant") for item in alice)
    assert any(item.access_name.endswith("rr-invoice-read") for item in alice)

    charlie = [
        item for item in evaluation.effective_accesses if item.identity_identifier == "charlie"
    ]
    role_x = next(item for item in charlie if item.access_name.endswith("rr-role-x"))
    assert len(role_x.paths) == 2
    assert any(item["type"] == "cycle_detected" for item in evaluation.diagnostics)


def test_keycloak_v0_service_account_role_mapping_is_not_human(tmp_path: Path) -> None:
    result = import_keycloak_zip(_artifact(tmp_path))
    evaluation = calculate_effective_accesses(
        result.assignments, result.access_relations, result.accesses
    )

    service = next(item for item in result.identities if item.native_id == "u-backup")
    assert service.type == "technical_account"
    assert any(
        item.identity_identifier == service.identifier
        and item.access_name == "client:c-crm:role:cr-backup"
        for item in evaluation.effective_accesses
    )


def test_keycloak_v0_replay_is_deterministic(tmp_path: Path) -> None:
    first = import_keycloak_zip(_artifact(tmp_path))
    second = import_keycloak_zip(_artifact(tmp_path))

    def projection(result):
        return {
            "identities": sorted(
                (item.identifier, item.native_id, item.type, item.status)
                for item in result.identities
            ),
            "accesses": sorted(
                (
                    item.provider,
                    item.name,
                    item.control_object.native_id if item.control_object else None,
                )
                for item in result.accesses
            ),
            "assignments": sorted(
                (item.access_name, item.identity_identifier, item.origin.fingerprint())
                for item in result.assignments
            ),
            "relations": sorted(item.key() for item in result.access_relations or []),
        }

    assert projection(first) == projection(second)


def test_full_contract_requires_all_surfaces_and_completed_files(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="must complete every V1 surface"):
        import_keycloak_zip(
            _custom_artifact(
                tmp_path,
                manifest_changes={"requested_surfaces": ["users"], "completed_surfaces": ["users"]},
            )
        )
    with pytest.raises(ValueError, match="missing group-role-mappings.jsonl"):
        import_keycloak_zip(_custom_artifact(tmp_path, omitted={"group-role-mappings.jsonl"}))


@pytest.mark.parametrize(
    "changes",
    [
        {"requested_surfaces": ["users", "users"]},
        {"requested_surfaces": ["users", "not-a-surface"]},
        {"completed_surfaces": ["users", "clients"], "requested_surfaces": ["users"]},
        {"completeness": "made-up"},
    ],
)
def test_surface_contract_rejects_unknown_duplicate_or_invalid_values(
    tmp_path: Path, changes: dict
) -> None:
    with pytest.raises(ValueError, match="invalid"):
        import_keycloak_zip(_custom_artifact(tmp_path, manifest_changes=changes))


def test_full_rejects_unresolved_references_and_unknown_client(tmp_path: Path) -> None:
    mappings = [
        {"id": "um-1", "user_id": "u-alice", "role_kind": "realm", "role_id": "missing"},
        {"id": "um-2", "user_id": "u-bob", "role_kind": "realm", "role_id": "rr-accountant"},
        {
            "id": "um-3",
            "user_id": "u-backup",
            "role_kind": "client",
            "role_id": "cr-backup",
            "client_id": "c-crm",
        },
    ]
    with pytest.raises(ValueError, match="unresolved structural references"):
        import_keycloak_zip(
            _custom_artifact(
                tmp_path,
                row_changes={"user-role-mappings.jsonl": mappings},
            )
        )
    roles = [
        {"id": "cr-sales", "client_id": "missing-client", "name": "Sales", "role_kind": "client"},
        {"id": "cr-backup", "client_id": "c-crm", "name": "Backup-Operator", "role_kind": "client"},
        {"id": "cr-crm-admin", "client_id": "c-crm", "name": "admin", "role_kind": "client"},
        {"id": "cr-erp-admin", "client_id": "c-erp", "name": "admin", "role_kind": "client"},
        {"id": "cr-erp-read", "client_id": "c-erp", "name": "Read", "role_kind": "client"},
    ]
    with pytest.raises(ValueError, match="unresolved structural references"):
        import_keycloak_zip(_custom_artifact(tmp_path, row_changes={"client-roles.jsonl": roles}))


def test_service_account_can_be_standalone_and_client_target_is_human_readable(
    tmp_path: Path,
) -> None:
    users = [row for row in _rows("users.jsonl") if row["id"] != "u-backup"]
    result = import_keycloak_zip(
        _custom_artifact(
            tmp_path,
            row_changes={"users.jsonl": users},
        )
    )
    service = next(item for item in result.identities if item.native_id == "u-backup")
    assert service.type == "technical_account"
    crm_admin = next(
        item for item in result.accesses if item.name == "client:c-crm:role:cr-crm-admin"
    )
    assert crm_admin.target.component == {"identifier": "c-crm"}
    assert crm_admin.control_object.metadata["client_display_name"] == "CRM"


def _v2_artifact(tmp_path: Path) -> Path:
    output = _artifact(tmp_path)
    v2 = tmp_path / "keycloak-v2.zip"
    authz = {
        "authorization-resources.jsonl": [
            {
                "id": "resource-invoices",
                "client_uuid": "c-erp",
                "clientId": "erp",
                "name": "Invoices",
            },
            {
                "id": "resource-contacts",
                "client_uuid": "c-crm",
                "clientId": "crm",
                "name": "Contacts",
            },
        ],
        "authorization-scopes.jsonl": [
            {"id": "scope-read", "client_uuid": "c-erp", "clientId": "erp", "name": "read"},
            {
                "id": "scope-download",
                "client_uuid": "c-erp",
                "clientId": "erp",
                "name": "download-report",
            },
        ],
        "authorization-policies.jsonl": [
            {
                "id": "policy-erp-read",
                "client_uuid": "c-erp",
                "clientId": "erp",
                "name": "ERP Reader",
                "type": "role",
                "logic": "POSITIVE",
                "config": {"roles": [{"id": "cr-erp-read"}]},
            },
            {
                "id": "policy-erp-complex",
                "client_uuid": "c-erp",
                "clientId": "erp",
                "name": "ERP Dynamic",
                "type": "aggregate",
                "decisionStrategy": "UNANIMOUS",
            },
        ],
        "authorization-permissions.jsonl": [
            {
                "id": "permission-erp-read",
                "client_uuid": "c-erp",
                "clientId": "erp",
                "name": "Invoices read",
                "resourceIds": ["resource-invoices"],
                "scopes": ["scope-read"],
                "policies": ["policy-erp-read"],
            },
            {
                "id": "permission-erp-complex",
                "client_uuid": "c-erp",
                "clientId": "erp",
                "name": "Invoices dynamic",
                "resourceIds": ["resource-invoices"],
                "scopes": ["scope-download"],
                "policies": ["policy-erp-complex"],
            },
        ],
    }
    with ZipFile(output) as source, ZipFile(v2, "w", ZIP_DEFLATED) as target:
        for info in source.infolist():
            target.writestr(info.filename, source.read(info.filename))
        for filename, rows in authz.items():
            target.writestr(filename, "".join(json.dumps(row) + "\n" for row in rows))
    return v2


def test_keycloak_v2_authz_derives_only_safe_functional_rights(tmp_path: Path) -> None:
    result = import_keycloak_zip(_v2_artifact(tmp_path))

    assert result.functional_access_models is not None
    model = next(
        item
        for item in result.functional_access_models
        if item.access_name == "client:c-erp:role:cr-erp-read"
    )
    assert model.completeness == "complete"
    assert len(model.rights) == 1
    assert model.rights[0].capability_id == "read"
    assert model.rights[0].target.resource["identifier"] == "resource-invoices"
    assert model.rights[0].native_permission == "scope:scope-read"
    assert model.rights[0].provenance == "mapped"
    assert not any(item.capability_id == "download-report" for item in model.rights)


def test_keycloak_v1_artifact_without_authz_remains_unchanged(tmp_path: Path) -> None:
    result = import_keycloak_zip(_artifact(tmp_path))
    assert result.batch.completeness == "full"
    assert result.functional_access_models == []


def _rows(filename: str) -> list[dict]:
    return [json.loads(line) for line in (FIXTURE / filename).read_text().splitlines() if line]


def test_rename_keeps_native_identity_access_and_client_keys(tmp_path: Path) -> None:
    renamed = import_keycloak_zip(
        _custom_artifact(
            tmp_path,
            row_changes={
                "users.jsonl": [
                    {
                        **row,
                        "username": "alice.renamed" if row["id"] == "u-alice" else row["username"],
                    }
                    for row in _rows("users.jsonl")
                ],
                "groups.jsonl": [
                    {
                        **row,
                        "name": "Finance Corporate" if row["id"] == "g-finance" else row["name"],
                    }
                    for row in _rows("groups.jsonl")
                ],
                "realm-roles.jsonl": [
                    {
                        **row,
                        "name": "Finance Accountant"
                        if row["id"] == "rr-accountant"
                        else row["name"],
                    }
                    for row in _rows("realm-roles.jsonl")
                ],
                "clients.jsonl": [
                    {**row, "name": "CRM Renamed", "clientId": "crm-renamed"}
                    if row["id"] == "c-crm"
                    else row
                    for row in _rows("clients.jsonl")
                ],
            },
        )
    )
    assert (
        next(item for item in renamed.identities if item.native_id == "u-alice").identifier
        == "alice.renamed"
    )
    assert (
        next(item for item in renamed.identities if item.native_id == "g-finance").native_id
        == "g-finance"
    )
    role = next(
        item
        for item in renamed.accesses
        if item.control_object and item.control_object.native_id == "rr-accountant"
    )
    assert role.name == "realm:production:role:rr-accountant"
    client_role = next(
        item
        for item in renamed.accesses
        if item.control_object and item.control_object.native_id == "cr-sales"
    )
    assert client_role.name == "client:c-crm:role:cr-sales"


def test_duplicate_identical_rows_dedupe_and_conflicts_reject(tmp_path: Path) -> None:
    users = _rows("users.jsonl")
    with pytest.raises(ValueError, match="conflicting duplicate"):
        import_keycloak_zip(
            _custom_artifact(
                tmp_path,
                row_changes={"users.jsonl": [*users, {**users[0], "email": "other@example.test"}]},
            )
        )
    result = import_keycloak_zip(
        _custom_artifact(tmp_path, row_changes={"users.jsonl": [*users, users[0]]})
    )
    assert len([item for item in result.identities if item.native_id == "u-alice"]) == 1


def test_archive_bounds_reject_oversized_record(tmp_path: Path) -> None:
    rows = _rows("users.jsonl")
    rows[0]["oversized"] = "x" * 2_000_001
    with pytest.raises(ValueError, match="JSONL record"):
        import_keycloak_zip(_custom_artifact(tmp_path, row_changes={"users.jsonl": rows}))


def test_keycloak_artifact_persists_and_scoped_replay_does_not_delete(tmp_path: Path) -> None:
    db = tmp_path / "eare.db"
    full = _artifact(tmp_path)
    with Repository(db) as repo:
        import_file_to_repository(repo, full)
        assignments = repo.list_payloads_by_provider("access_assignments", "keycloak-v0")
        assert any(row["access_name"] == "client:c-crm:role:cr-sales" for row in assignments)
        first_counts = {
            table: len(repo.list_payloads_by_provider(table, "keycloak-v0"))
            for table in ("identities", "accesses", "access_assignments", "access_relations")
        }
        import_file_to_repository(repo, full)
        assert {
            table: len(repo.list_payloads_by_provider(table, "keycloak-v0"))
            for table in first_counts
        } == first_counts
        renamed = _custom_artifact(
            tmp_path,
            row_changes={
                "users.jsonl": [
                    {**row, "username": "alice.renamed"}
                    if row["id"] == "u-alice"
                    else row
                    for row in _rows("users.jsonl")
                ],
                "groups.jsonl": [
                    {**row, "name": "Finance Corporate"}
                    if row["id"] == "g-finance"
                    else row
                    for row in _rows("groups.jsonl")
                ],
            },
        )
        import_file_to_repository(repo, renamed)
        identities = repo.list_payloads_by_provider("identities", "keycloak-v0")
        assert len([row for row in identities if row["native_id"] == "u-alice"]) == 1
        assert (
            next(row for row in identities if row["native_id"] == "u-alice")["identifier"]
            == "alice.renamed"
        )
        accesses = repo.list_payloads_by_provider("accesses", "keycloak-v0")
        assert (
            len(
                [
                    row
                    for row in accesses
                    if row.get("control_object", {}).get("native_id") == "rr-accountant"
                ]
            )
            == 1
        )

    scoped = _custom_artifact(
        tmp_path,
        manifest_changes={
            "completeness": "scoped",
            "requested_surfaces": [
                "users",
                "groups",
                "memberships",
                "clients",
                "realm_roles",
                "client_roles",
                "group_role_mappings",
                "composite_roles",
                "service_accounts",
            ],
            "completed_surfaces": [
                "users",
                "groups",
                "memberships",
                "clients",
                "realm_roles",
                "client_roles",
                "group_role_mappings",
                "composite_roles",
                "service_accounts",
            ],
        },
        row_changes={"user-role-mappings.jsonl": []},
    )
    with Repository(db) as repo:
        import_file_to_repository(repo, scoped)
        assignments = repo.list_payloads_by_provider("access_assignments", "keycloak-v0")
        assert any(row["access_name"] == "client:c-crm:role:cr-sales" for row in assignments)

    full_removed = _custom_artifact(tmp_path, row_changes={"user-role-mappings.jsonl": []})
    with Repository(db) as repo:
        import_file_to_repository(repo, full_removed)
        assignments = repo.list_payloads_by_provider("access_assignments", "keycloak-v0")
        assert not any(row["access_name"] == "client:c-crm:role:cr-sales" for row in assignments)
