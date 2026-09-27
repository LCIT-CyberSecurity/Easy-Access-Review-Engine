from __future__ import annotations

import json
from pathlib import Path
from zipfile import ZipFile

import yaml

from access_review_engine.application import _apply_keycloak_authoritative_scope
from access_review_engine.collectors.keycloak import KeycloakError, _retry, collect
from access_review_engine.config_loader import ConfigError, validate_connector

SURFACES = (
    "users",
    "groups",
    "memberships",
    "clients",
    "realm_roles",
    "client_roles",
    "user_role_mappings",
    "group_role_mappings",
    "composite_roles",
    "service_accounts",
)


class FakeKeycloak:
    def __init__(self, page_size: int = 2) -> None:
        self.page_size = page_size
        self.calls: list[tuple[str, int, dict[str, object]]] = []
        self.rows = {
            "users": [{"id": "u-alice", "username": "alice", "enabled": True}],
            "groups": [
                {
                    "id": "g-finance",
                    "name": "Finance",
                    "subGroups": [{"id": "g-fr", "name": "Finance-France"}],
                }
            ],
            "clients": [{"id": "c-crm", "clientId": "crm", "name": "CRM"}],
            "realm_roles": [{"id": "rr-accountant", "name": "accountant", "composite": True}],
            "client_roles": [{"id": "cr-sales", "name": "sales", "composite": False}],
            "memberships": [{"id": "u-alice"}],
            "user_role_mappings": [
                {
                    "id": "cr-sales",
                    "role_kind": "client",
                    "role_id": "cr-sales",
                    "client_id": "c-crm",
                    "user_id": "u-alice",
                }
            ],
            "group_role_mappings": [
                {
                    "id": "rr-accountant",
                    "role_kind": "realm",
                    "role_id": "rr-accountant",
                    "group_id": "g-finance",
                }
            ],
            "composite_roles": [{"id": "rr-invoice", "name": "invoice-read", "role_kind": "realm"}],
            "service_accounts": [],
            "composites": [{"id": "rr-invoice", "name": "invoice-read", "role_kind": "realm"}],
        }

    def list(
        self, surface: str, page: int, page_size: int, **kwargs: object
    ) -> list[dict[str, object]]:
        self.calls.append((surface, page, kwargs))
        if surface == "memberships":
            return self.rows[surface] if kwargs["group"]["id"] == "g-fr" else []  # type: ignore[index]
        if surface == "client_roles":
            return self.rows[surface] if kwargs["client"]["id"] == "c-crm" else []  # type: ignore[index]
        if surface == "service_accounts":
            return []
        if surface == "composites":
            return self.rows[surface]
        if surface in {"user_role_mappings", "group_role_mappings"}:
            key = "users" if surface.startswith("user") else "groups"
            return self.rows[surface] if kwargs["subject"]["id"] == self.rows[key][0]["id"] else []  # type: ignore[index]
        values = self.rows[surface]
        return values[page * page_size : (page + 1) * page_size]


def _config() -> dict[str, object]:
    return {
        "provider": "keycloak-test",
        "type": "keycloak",
        "connection": {
            "base_url": "https://keycloak.test",
            "realm": "eare-crashtest",
            "client_id": "eare-collector",
        },
        "credentials": {"client_secret_env": "EARE_KEYCLOAK_SECRET_CANARY_DO_NOT_LEAK"},
        "collection": {
            **{surface: True for surface in SURFACES},
            "page_size": 2,
            "timeout": 5,
            "allow_partial": False,
        },
    }


def test_live_collector_emits_the_v0_contract_and_paginates(tmp_path: Path) -> None:
    output = tmp_path / "keycloak.zip"
    fake = FakeKeycloak()
    manifest = collect(_config(), output, fake)
    assert manifest["completeness"] == "full"
    assert set(manifest["completed_surfaces"]) == set(SURFACES)
    assert manifest["realm"] == "eare-crashtest"
    assert any(surface == "groups" and page == 1 for surface, page, _ in fake.calls) is False
    with ZipFile(output) as archive:
        assert "manifest.yaml" in archive.namelist()
        assert json.loads(archive.read("collection-errors.json")) == []
        assert b"EARE_KEYCLOAK_SECRET_CANARY_DO_NOT_LEAK" not in archive.read("manifest.yaml")
        parsed = yaml.safe_load(archive.read("manifest.yaml"))
        assert parsed["counts"]["groups"] == 2


def test_keycloak_config_requires_secret_reference_and_realm() -> None:
    config = _config()
    validate_connector(config)
    config["credentials"] = {"client_secret": "plaintext"}
    try:
        validate_connector(config)
    except ConfigError:
        pass
    else:
        raise AssertionError("plaintext Keycloak secret was accepted")


def test_keycloak_config_rejects_invalid_page_size() -> None:
    config = _config()
    config["collection"]["page_size"] = 0  # type: ignore[index]
    try:
        validate_connector(config)
    except ConfigError as exc:
        assert "page_size" in str(exc)
    else:
        raise AssertionError("invalid page size was accepted")


def test_keycloak_retry_is_bounded_and_only_retries_transient_errors() -> None:
    attempts = 0

    def flaky() -> list[dict[str, object]]:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise KeycloakError("temporary", 503)
        return []

    assert _retry(flaky, sleep=lambda _: None) == []
    assert attempts == 3

    def forbidden() -> list[dict[str, object]]:
        raise KeycloakError("forbidden", 403)

    try:
        _retry(forbidden, sleep=lambda _: None)
    except KeycloakError as exc:
        assert exc.status_code == 403
    else:
        raise AssertionError("403 was retried or swallowed")


def test_keycloak_realm_scope_change_is_rejected() -> None:
    scope = {"connector_type": "keycloak", "realm": "staging", "surfaces": list(SURFACES)}
    try:
        _apply_keycloak_authoritative_scope(
            scope,
            [
                {
                    "authoritative_scope": {
                        "connector_type": "keycloak",
                        "realm": "production",
                        "surfaces": list(SURFACES),
                    }
                }
            ],
        )
    except ValueError as exc:
        assert str(exc) == "KEYCLOAK_REALM_SCOPE_CHANGED"
    else:
        raise AssertionError("realm scope change was accepted")
