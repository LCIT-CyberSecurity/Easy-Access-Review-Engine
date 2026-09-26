from __future__ import annotations

import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from access_review_engine.application import persist_import_result
from access_review_engine.collectors.gcp_iam import collect as collect_gcp
from access_review_engine.collectors.google_workspace import collect as collect_workspace
from access_review_engine.google_artifacts import read_artifact
from access_review_engine.importers.gcp_iam import import_gcp_iam_zip
from access_review_engine.importers.google_workspace import import_google_workspace_zip
from access_review_engine.services import calculate_effective_accesses
from access_review_engine.storage import Repository


class FakeWorkspace:
    def __init__(self):
        self.calls = []

    def list(self, surface, page_token, page_size, group_id=None):
        self.calls.append((surface, page_token, page_size, group_id))
        if surface == "users":
            return {
                None: {
                    "users": [
                        {
                            "id": "u1",
                            "primaryEmail": "alice@example.com",
                            "name": {"fullName": "Alice"},
                        }
                    ],
                    "nextPageToken": "u2",
                },
                "u2": {"users": [], "nextPageToken": "u3"},
                "u3": {
                    "users": [
                        {"id": "u2", "primaryEmail": "bob@example.com", "name": {"fullName": "Bob"}}
                    ]
                },
            }[page_token]
        if surface == "groups":
            return {
                "groups": [
                    {"id": "g1", "email": "developers@example.com", "displayName": "Developers"}
                ]
            }
        if surface == "memberships":
            return {
                None: {
                    "members": [
                        {"id": "u1", "email": "alice@example.com", "type": "USER", "role": "MEMBER"}
                    ],
                    "nextPageToken": "m2",
                },
                "m2": {
                    "members": [
                        {"id": "u2", "email": "bob@example.com", "type": "USER", "role": "MANAGER"}
                    ]
                },
            }[page_token]
        if surface == "admin_roles":
            return {"items": [{"roleId": "r1", "roleName": "Help Desk"}]}
        return {"items": [{"roleAssignmentId": "ra1", "roleId": "r1", "assignedTo": "u1"}]}


class FakeGcp:
    def list_bindings(self, scope, page_token):
        return (
            {
                "results": [
                    {
                        "resource": "projects/prod",
                        "assetType": "cloudresourcemanager.googleapis.com/Project",
                        "project": "projects/prod",
                        "policy": {
                            "bindings": [
                                {
                                    "role": "roles/editor",
                                    "members": ["group:developers@example.com"],
                                    "condition": {
                                        "expression": "request.time < timestamp('2030-01-01T00:00:00Z')",
                                        "title": "expiry",
                                    },
                                }
                            ]
                        },
                    }
                ],
                "nextPageToken": "next",
            }
            if not page_token
            else {"results": []}
        )

    def list_service_accounts(self, scope, page_token):
        return {
            "serviceAccounts": [{"email": "backup@prod.iam.gserviceaccount.com", "uniqueId": "sa1"}]
        }


def _artifact(path: Path, manifest: dict, files: dict[str, list[dict]]) -> None:
    with ZipFile(path, "w", ZIP_DEFLATED) as archive:
        import yaml

        archive.writestr("manifest.yaml", yaml.safe_dump(manifest))
        for name, rows in files.items():
            archive.writestr(
                name,
                json.dumps(rows)
                if name == "collection-errors.json"
                else "".join(json.dumps(row) + "\n" for row in rows),
            )


def test_workspace_collector_paginates_empty_page_and_imports_model(tmp_path):
    output = tmp_path / "workspace.zip"
    config = {
        "provider": "workspace-acme",
        "connection": {"customer_id": "my_customer", "delegated_admin": "admin@example.com"},
        "collection": {"page_size": 200},
    }
    manifest = collect_workspace(config, output, FakeWorkspace())
    assert manifest["completeness"] == "full"
    result = import_google_workspace_zip(output)
    alice = next(
        identity for identity in result.identities if identity.identifier == "alice@example.com"
    )
    assert alice.native_id == "u1"
    assert {
        access.metadata["membership_role"]
        for access in result.accesses
        if access.control_object and access.control_object.type == "google_group"
    } == {"MEMBER", "MANAGER", "OWNER"}
    assert any(
        assignment.identity_identifier == alice.identifier for assignment in result.assignments
    )


def test_workspace_rename_keeps_native_identity(tmp_path):
    path = tmp_path / "workspace.zip"
    _artifact(
        path,
        {"source_type": "google_workspace", "provider": "workspace-acme", "completeness": "full"},
        {
            "users.jsonl": [{"id": "u1", "primaryEmail": "alice.martin@example.com"}],
            "groups.jsonl": [],
            "memberships.jsonl": [],
            "admin-roles.jsonl": [],
            "admin-role-assignments.jsonl": [],
            "collection-errors.json": [],
        },
    )
    result = import_google_workspace_zip(path)
    identity = result.identities[0]
    assert identity.native_id == "u1" and identity.identifier == "alice.martin@example.com"


def test_gcp_conditions_and_special_principals_are_preserved(tmp_path):
    output = tmp_path / "gcp.zip"
    config = {"provider": "gcp-acme", "connection": {"scope": "projects/prod"}, "collection": {}}
    manifest = collect_gcp(config, output, FakeGcp())
    assert manifest["pages"]["iam_allow_policies"] == 2
    result = import_gcp_iam_zip(output)
    assert result.accesses[0].permission.identifier == "roles/editor"
    assert result.accesses[0].metadata["condition"]["expression"].startswith("request.time")


def test_workspace_group_graph_derives_effective_access_without_fake_assignment(tmp_path):
    path = tmp_path / "workspace.zip"
    _artifact(
        path,
        {"source_type": "google_workspace", "provider": "workspace-acme", "completeness": "full"},
        {
            "users.jsonl": [{"id": "u1", "primaryEmail": "alice@example.com"}],
            "groups.jsonl": [
                {"id": "g1", "email": "developers@example.com"},
                {"id": "g2", "email": "cloud-admins@example.com"},
            ],
            "memberships.jsonl": [
                {"group_id": "g1", "member_id": "u1", "role": "MEMBER"},
                {"group_id": "g2", "member_id": "g1", "role": "MEMBER"},
            ],
            "admin-roles.jsonl": [],
            "admin-role-assignments.jsonl": [],
            "collection-errors.json": [],
        },
    )
    result = import_google_workspace_zip(path)
    evaluation = calculate_effective_accesses(
        result.assignments, result.access_relations, result.accesses
    )
    assert any(access.access_name.endswith("g2:MEMBER") for access in evaluation.effective_accesses)
    assert not any(
        assignment.identity_identifier == "alice@example.com"
        and assignment.access_name.endswith("g2:MEMBER")
        for assignment in result.assignments
    )


def test_partial_workspace_import_does_not_delete_previous_identity(tmp_path):
    first = tmp_path / "first.zip"
    _artifact(
        first,
        {"source_type": "google_workspace", "provider": "workspace-acme", "completeness": "full"},
        {
            "users.jsonl": [{"id": "u1", "primaryEmail": "alice@example.com"}],
            "groups.jsonl": [],
            "memberships.jsonl": [],
            "admin-roles.jsonl": [],
            "admin-role-assignments.jsonl": [],
            "collection-errors.json": [],
        },
    )
    partial = tmp_path / "partial.zip"
    _artifact(
        partial,
        {
            "source_type": "google_workspace",
            "provider": "workspace-acme",
            "completeness": "scoped",
            "collection_errors": [{"surface": "users"}],
        },
        {
            "users.jsonl": [],
            "groups.jsonl": [],
            "memberships.jsonl": [],
            "admin-roles.jsonl": [],
            "admin-role-assignments.jsonl": [],
            "collection-errors.json": [{"surface": "users"}],
        },
    )
    with Repository(tmp_path / "eare.db") as repo:
        persist_import_result(repo, import_google_workspace_zip(first))
        persist_import_result(repo, import_google_workspace_zip(partial))
        assert any(
            row["identifier"] == "alice@example.com" for row in repo.list_payloads("identities")
        )


def test_workspace_roles_join_assignments_and_group_access_ids(tmp_path):
    path = tmp_path / "roles.zip"
    _artifact(
        path,
        {"source_type": "google_workspace", "provider": "w", "completeness": "full"},
        {
            "users.jsonl": [
                {
                    "id": "u1",
                    "primaryEmail": "alice@example.com",
                    "name": {"fullName": "Alice Martin"},
                }
            ],
            "groups.jsonl": [{"id": "g1", "email": "admins@example.com", "displayName": "Admins"}],
            "memberships.jsonl": [
                {
                    "group_id": "g1",
                    "member_id": "missing",
                    "member_email": "unknown@example.com",
                    "member_type": "USER",
                    "role": "OWNER",
                }
            ],
            "admin-roles.jsonl": [
                {
                    "roleId": "r1",
                    "roleName": "Help Desk",
                    "roleDescription": "Support",
                    "isSystemRole": True,
                }
            ],
            "admin-role-assignments.jsonl": [
                {
                    "roleAssignmentId": "ra1",
                    "roleId": "r1",
                    "assignedTo": "g1",
                    "assigneeType": "GROUP",
                    "scopeType": "CUSTOMER",
                }
            ],
            "collection-errors.json": [],
        },
    )
    result = import_google_workspace_zip(path)
    alice = next(item for item in result.identities if item.identifier == "alice@example.com")
    assert alice.display_name == "Alice Martin"
    group_accesses = [
        item
        for item in result.accesses
        if item.metadata.get("source_group") == "admins@example.com"
    ]
    assert {item.control_object.native_id for item in group_accesses} == {
        f"google-group:g1:{role}" for role in ("MEMBER", "MANAGER", "OWNER")
    }
    assert any(item.metadata.get("unresolved") for item in result.identities)
    assert any(item.identity_identifier == "unknown@example.com" for item in result.assignments)
    role_access = next(item for item in result.accesses if item.metadata.get("role_id") == "r1")
    assert role_access.display_name == "Help Desk"


def test_gcp_principal_parser_keeps_special_and_deleted_principals(tmp_path):
    path = tmp_path / "principals.zip"
    rows = [
        {
            "resource": "projects/p",
            "role": "roles/viewer",
            "members": [
                "user:alice@example.com",
                "group:admins@example.com",
                "serviceAccount:sa@p.iam.gserviceaccount.com",
                "domain:example.com",
                "allUsers",
                "allAuthenticatedUsers",
                "deleted:user:gone@example.com",
                "deleted:serviceAccount:old@p.iam.gserviceaccount.com",
                "principal://iam.googleapis.com/x",
                "principalSet://iam.googleapis.com/y",
                "unknown:raw",
            ],
        }
    ]
    _artifact(
        path,
        {"source_type": "gcp_iam", "provider": "g", "completeness": "full"},
        {
            "iam-bindings.jsonl": rows,
            "service-accounts.jsonl": [],
            "resource-hierarchy.jsonl": [],
            "collection-errors.json": [],
        },
    )
    result = import_gcp_iam_zip(path)
    assert all(item.identity_provider == "g" for item in result.assignments)
    assert not any(item.type == "unknown" for item in result.identities)
    assert any(item.identifier == "allUsers" and item.built_in for item in result.identities)
    assert any(
        item.status == "deleted" and item.identifier == "gone@example.com"
        for item in result.identities
    )
    assert any(
        item.metadata.get("principal", "").startswith("principalSet://")
        for item in result.identities
    )


def test_gcp_flags_do_not_call_disabled_surfaces(tmp_path):
    class Client(FakeGcp):
        def __init__(self):
            self.calls = []

        def list_bindings(self, scope, page_token):
            self.calls.append("iam")
            return {"results": []}

        def list_service_accounts(self, scope, page_token):
            self.calls.append("sa")
            return {"serviceAccounts": []}

    client = Client()
    collect_gcp(
        {
            "provider": "g",
            "connection": {"scope": "projects/p"},
            "collection": {"iam_allow_policies": True, "service_accounts": False},
        },
        tmp_path / "g.zip",
        client,
    )
    assert client.calls == ["iam"]


def test_full_artifact_rejects_missing_completed_file_and_bad_count(tmp_path):
    path = tmp_path / "bad.zip"
    _artifact(
        path,
        {
            "source_type": "google_workspace",
            "provider": "w",
            "completeness": "full",
            "requested_surfaces": ["users"],
            "completed_surfaces": ["users"],
            "counts": {"users": 1},
        },
        {"collection-errors.json": []},
    )
    with __import__("pytest").raises(ValueError):
        read_artifact(path, "google_workspace", {"users.jsonl", "collection-errors.json"})


def test_gcp_condition_title_is_not_identity_but_expression_is(tmp_path):
    def make(name, expression):
        path = tmp_path / f"{name}.zip"
        _artifact(
            path,
            {"source_type": "gcp_iam", "provider": "g", "completeness": "full"},
            {
                "iam-bindings.jsonl": [
                    {
                        "resource": "projects/p",
                        "role": "roles/viewer",
                        "members": ["user:a@example.com"],
                        "condition": {"title": name, "expression": expression},
                    }
                ],
                "service-accounts.jsonl": [],
                "resource-hierarchy.jsonl": [],
                "collection-errors.json": [],
            },
        )
        return import_gcp_iam_zip(path).accesses[0].name

    assert make("one", "request.time < timestamp('2030-01-01T00:00:00Z')") == make(
        "two", "request.time < timestamp('2030-01-01T00:00:00Z')"
    )
    assert make("three", "request.time < timestamp('2031-01-01T00:00:00Z')") != make(
        "four", "request.time < timestamp('2030-01-01T00:00:00Z')"
    )


def test_gcp_assignment_resolves_after_workspace_import_and_alias(tmp_path):
    gcp = tmp_path / "gcp.zip"
    _artifact(
        gcp,
        {
            "source_type": "gcp_iam",
            "provider": "g",
            "completeness": "full",
            "authoritative_scope": {
                "connector_type": "gcp_iam",
                "scope": "projects/p",
                "surfaces": ["iam_allow_policies"],
            },
        },
        {
            "iam-bindings.jsonl": [
                {
                    "resource": "projects/p",
                    "role": "roles/viewer",
                    "members": ["user:alice@example.com"],
                }
            ],
            "service-accounts.jsonl": [],
            "resource-hierarchy.jsonl": [],
            "collection-errors.json": [],
        },
    )
    workspace = tmp_path / "workspace.zip"
    _artifact(
        workspace,
        {
            "source_type": "google_workspace",
            "provider": "w",
            "completeness": "full",
            "authoritative_scope": {
                "connector_type": "google_workspace",
                "customer_id": "c",
                "surfaces": ["users"],
            },
        },
        {
            "users.jsonl": [
                {
                    "id": "u1",
                    "primaryEmail": "alice.martin@example.com",
                    "aliases": ["alice@example.com"],
                }
            ],
            "groups.jsonl": [],
            "memberships.jsonl": [],
            "admin-roles.jsonl": [],
            "admin-role-assignments.jsonl": [],
            "collection-errors.json": [],
        },
    )
    with Repository(tmp_path / "eare.db") as repo:
        gcp_result = import_gcp_iam_zip(gcp)
        assert gcp_result.assignments[0].origin.raw.get("unresolved") is True
        persist_import_result(repo, gcp_result)
        persist_import_result(repo, import_google_workspace_zip(workspace, known_identities=[]))
        from access_review_engine.application import _resolve_unresolved_assignments

        _resolve_unresolved_assignments(repo)
        assignments = repo.list_payloads("access_assignments")
        assert any(
            item["identity_provider"] == "w"
            and item["identity_identifier"] == "alice.martin@example.com"
            for item in assignments
        )
        assert not any(
            item["status"] == "active" and item.get("metadata", {}).get("unresolved")
            for item in repo.list_payloads("identities")
        )
