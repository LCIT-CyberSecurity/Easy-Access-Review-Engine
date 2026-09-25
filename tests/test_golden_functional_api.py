from __future__ import annotations

import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from access_review_engine.api import create_app
from access_review_engine.storage import Repository
from access_review_engine.system_admin import init_system, upsert_user


def _client(db: Path, username: str, role: str) -> TestClient:
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    init_system(conn)
    upsert_user(conn, {"username": username, "role": role, "scopes": ["*"], "password": "test-password"})
    conn.close()
    client = TestClient(create_app(str(db)))
    response = client.post(
        "/api/auth/login", json={"username": username, "password": "test-password"}
    )
    assert response.status_code == 200
    return client


def test_golden_functional_model_creates_immutable_v2_and_reads_effective_rights(tmp_path):
    db = tmp_path / "golden-functional.db"
    client = _client(db, "operator", "OPERATOR")
    created = client.post(
        "/api/golden-sources/from-scratch",
        json={"name": "crm"},
    )
    assert created.status_code == 200

    response = client.post(
        "/api/golden-sources/crm/functional-model",
        json={
            "access_provider": "openldap-corp",
            "access_name": "GG-CRM-Compta",
            "manual_access": True,
            "access_type": "group",
            "access_display_name": "CRM Accounting",
            "completeness": "partial",
            "rights": [
                {
                    "target": {
                        "service": {
                            "identifier": "nexabyte-crm",
                            "display_name": "NexaByte CRM",
                            "type": "application",
                        },
                        "resource": {
                            "identifier": "invoices",
                            "display_name": "Invoices",
                            "type": "business_object",
                        },
                    },
                    "capability_id": "read",
                    "native_permission": "SELECT",
                }
            ],
            "grants": [],
            "access_comment": "Accounting access",
            "version_comment": "Document expected CRM rights",
        },
    )
    assert response.status_code == 200
    assert response.json()["schema_version"] == 2
    assert response.json()["version"] == 2

    model = client.get("/api/golden-sources/crm/functional-model")
    assert model.status_code == 200
    item = next(row for row in model.json()["items"] if row["access_name"] == "GG-CRM-Compta")
    assert item["completeness"] == "partial"
    assert item["effective_right_count"] == 1
    assert item["functional_rights"][0]["capability_id"] == "read"
    assert item["functional_rights"][0]["native_permission"] == "SELECT"
    assert item["direct_functional_rights"][0]["capability_id"] == "read"
    assert item["direct_functional_rights"][0]["native_permission"] == "SELECT"
    assert item["direct_functional_rights"][0]["provenance"] == "manual"
    assert item["effective_functional_rights"][0]["capability_id"] == "read"
    assert item["functional_rights"][0]["target_path"] == "NexaByte CRM › Invoices"
    assert item["access_comment"] == "Accounting access"

    with Repository(db) as repo:
        versions = repo.list_payloads("golden_source_versions")
        first = next(version for version in versions if version["version"] == 1)
        second = next(version for version in versions if version["version"] == 2)
    assert first["schema_version"] == 1
    assert first["functional_access_models"] == []
    assert second["schema_version"] == 2
    assert second["functional_access_models"][0]["completeness"] == "partial"


def test_golden_functional_model_rejects_invalid_target_and_unmapped_capability(tmp_path):
    db = tmp_path / "golden-functional-invalid.db"
    client = _client(db, "operator", "OPERATOR")
    client.post("/api/golden-sources/from-scratch", json={"name": "crm"})
    payload = {
        "access_provider": "crm",
        "access_name": "CRM-Compta",
        "manual_access": True,
        "completeness": "complete",
        "rights": [
            {
                "target": {"service": {"identifier": "crm"}, "subresource": {"identifier": "x"}},
                "capability_id": "read",
            }
        ],
    }
    response = client.post("/api/golden-sources/crm/functional-model", json=payload)
    assert response.status_code == 400
    payload["rights"] = [
        {"target": {"resource": {"identifier": "invoices"}}, "capability_id": "membership"}
    ]
    response = client.post("/api/golden-sources/crm/functional-model", json=payload)
    assert response.status_code == 400
    with Repository(db) as repo:
        assert len(repo.list_payloads("golden_source_versions")) == 1


def test_capability_mutations_are_admin_only_and_mapping_keeps_native_permission(tmp_path):
    db = tmp_path / "capabilities-api.db"
    operator = _client(db, "operator", "OPERATOR")
    assert operator.get("/api/capabilities").status_code == 200
    assert operator.post(
        "/api/system/capabilities",
        json={"id": "export", "label": "Export", "description": "Export information."},
    ).status_code == 403

    admin = _client(db, "admin", "ADMIN")
    created = admin.post(
        "/api/system/capabilities",
        json={"id": "export", "label": "Export", "description": "Export business records."},
    )
    assert created.status_code == 200
    mapping = admin.post(
        "/api/system/permission-capability-mappings",
        json={
            "provider": "postgres",
            "permission_identifier": "SELECT",
            "capability_ids": ["read"],
        },
    )
    assert mapping.status_code == 200
    assert mapping.json()["mapping"]["permission_identifier"] == "SELECT"
    assert admin.get("/api/system/permission-capability-mappings").json()["mappings"][0][
        "permission_identifier"
    ] == "SELECT"
    deactivated = admin.post(
        "/api/system/capabilities",
        json={
            "id": "export",
            "label": "Export",
            "description": "Export business records.",
            "active": False,
        },
    )
    assert deactivated.status_code == 200
    assert deactivated.json()["capability"]["active"] is False
