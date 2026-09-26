from __future__ import annotations

import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from access_review_engine.application import persist_import_result
from access_review_engine.collectors.gcp_iam import collect as collect_gcp
from access_review_engine.collectors.google_workspace import collect as collect_workspace
from access_review_engine.importers.gcp_iam import import_gcp_iam_zip
from access_review_engine.importers.google_workspace import import_google_workspace_zip
from access_review_engine.services import calculate_effective_accesses
from access_review_engine.storage import Repository


class FakeWorkspace:
    def __init__(self):
        self.calls = []

    def list(self, surface, page_token, page_size):
        self.calls.append((surface, page_token, page_size))
        pages = {
            "users": (
                {
                    "items": [{"id": "u1", "primaryEmail": "alice@example.com", "name": "Alice"}],
                    "nextPageToken": "u2",
                }
                if not page_token
                else {"items": []}
            ),
            "groups": {
                "items": [
                    {"id": "g1", "email": "developers@example.com", "displayName": "Developers"}
                ]
            },
            "memberships": {"items": [{"group_id": "g1", "member_id": "u1", "role": "MEMBER"}]},
            "admin_roles": {"items": [{"roleId": "r1", "roleName": "Help Desk"}]},
            "admin_role_assignments": {
                "items": [{"id": "ra1", "roleId": "r1", "assignedTo": "u1"}]
            },
        }
        return pages[surface]


class FakeGcp:
    def list_bindings(self, scope, page_token):
        return (
            {
                "bindings": [
                    {
                        "resource": "projects/prod",
                        "role": "roles/editor",
                        "members": ["group:developers@example.com"],
                        "condition": {
                            "expression": "request.time < timestamp('2030-01-01T00:00:00Z')",
                            "title": "expiry",
                        },
                    }
                ],
                "nextPageToken": "next",
            }
            if not page_token
            else {"bindings": []}
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
