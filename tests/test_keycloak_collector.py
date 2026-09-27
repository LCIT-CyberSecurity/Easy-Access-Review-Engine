from __future__ import annotations

import json
from pathlib import Path
from zipfile import ZipFile

import yaml

from access_review_engine.application import _apply_keycloak_authoritative_scope
from access_review_engine.collectors.keycloak import KeycloakError, _HTTPClient, _retry, collect
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

    def check_realm(self) -> None:
        self.calls.append(("realm", 0, {}))

    def list(
        self, surface: str, page: int, page_size: int, **kwargs: object
    ) -> list[dict[str, object]]:
        self.calls.append((surface, page, kwargs))
        if surface == "memberships":
            values = self.rows[surface] if kwargs["group"]["id"] == "g-fr" else []  # type: ignore[index]
            return values[page * page_size : (page + 1) * page_size]
        if surface == "client_roles":
            values = self.rows[surface] if kwargs["client"]["id"] == "c-crm" else []  # type: ignore[index]
            return values[page * page_size : (page + 1) * page_size]
        if surface == "service_accounts":
            return []
        if surface == "composites":
            values = self.rows[surface]
            return values[page * page_size : (page + 1) * page_size]
        if surface in {"user_role_mappings", "group_role_mappings"}:
            key = "users" if surface.startswith("user") else "groups"
            values = (
                self.rows[surface]
                if kwargs["subject"]["id"] == self.rows[key][0]["id"]
                else []
            )  # type: ignore[index]
            return values[page * page_size : (page + 1) * page_size]
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


def test_keycloak_retry_covers_only_declared_transient_statuses() -> None:
    for status in (429, 502, 503, 504):
        attempts = 0

        def transient(status: int = status) -> list[dict[str, object]]:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise KeycloakError("temporary", status)
            return []

        assert _retry(transient, sleep=lambda _: None) == []
        assert attempts == 2

    for status in (400, 401, 403, 404, 500):
        attempts = 0

        def permanent(status: int = status) -> list[dict[str, object]]:
            nonlocal attempts
            attempts += 1
            raise KeycloakError("not retryable", status)

        try:
            _retry(permanent, sleep=lambda _: None)
        except KeycloakError:
            assert attempts == 1
        else:
            raise AssertionError(f"status {status} was retried or swallowed")


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


def test_check_only_uses_only_valid_parent_contexts(tmp_path: Path) -> None:
    config = _config()
    config["_check_only"] = True
    result = collect(config, tmp_path / "check.zip", FakeKeycloak())
    assert result["check_only"] is True
    assert {row["surface"] for row in result["diagnostics"]} >= {
        "authentication",
        "users",
        "groups",
        "clients",
        "realm_roles",
        "dependent_surfaces",
    }


def test_http_client_builds_read_only_admin_api_paths(monkeypatch) -> None:
    config = _config()
    monkeypatch.setenv("EARE_KEYCLOAK_SECRET_CANARY_DO_NOT_LEAK", "test-secret")
    monkeypatch.setattr(_HTTPClient, "_token", lambda _self: "t0")
    client = _HTTPClient(config)
    captured: list[tuple[str, dict[str, object]]] = []

    def fake_get(path: str, params: dict[str, object]) -> list[dict[str, object]]:
        captured.append((path, params))
        return []

    monkeypatch.setattr(client, "_get", fake_get)
    client.list("users", 0, 2)
    client.list("groups", 0, 2)
    client.list("clients", 0, 2)
    client.list("realm_roles", 0, 2)
    client.list("memberships", 0, 2, group={"id": "g/1"})
    client.list("client_roles", 0, 2, client={"id": "c/1"})
    client.list("user_role_mappings", 0, 2, subject={"id": "u/1"})
    client.list("group_role_mappings", 0, 2, subject={"id": "g/1"})
    client.list("composites", 0, 2, role={"name": "accountant"})
    client.list(
        "composites",
        0,
        2,
        role={"name": "sales"},
        client={"id": "c/1"},
    )
    client.list("service_accounts", 0, 1, client={"id": "c/1"})
    assert [path for path, _ in captured] == [
        "users",
        "groups",
        "clients",
        "roles",
        "groups/g%2F1/members",
        "clients/c%2F1/roles",
        "users/u%2F1/role-mappings",
        "groups/g%2F1/role-mappings",
        "roles/accountant/composites",
        "clients/c/1/roles/sales/composites",
        "clients/c%2F1/service-account-user",
    ]


class FailingSurface(FakeKeycloak):
    def __init__(self, surface: str) -> None:
        super().__init__()
        self.surface = surface

    def list(
        self, surface: str, page: int, page_size: int, **kwargs: object
    ) -> list[dict[str, object]]:
        if surface == self.surface:
            raise KeycloakError(f"{surface} unavailable", 403)
        return super().list(surface, page, page_size, **kwargs)


def test_partial_parent_failure_marks_dependent_surfaces_incomplete(tmp_path: Path) -> None:
    config = _config()
    config["collection"]["allow_partial"] = True  # type: ignore[index]
    manifest = collect(config, tmp_path / "partial.zip", FailingSurface("clients"))
    assert manifest["completeness"] == "scoped"
    assert "clients" not in manifest["completed_surfaces"]
    assert "client_roles" not in manifest["completed_surfaces"]
    assert "service_accounts" not in manifest["completed_surfaces"]
    assert {error["surface"] for error in manifest["collection_errors"]} >= {
        "clients",
        "client_roles",
        "service_accounts",
    }


def test_service_account_endpoint_is_singleton_even_with_page_size_one(tmp_path: Path) -> None:
    fake = FakeKeycloak(page_size=1)
    fake.rows["clients"][0]["serviceAccountsEnabled"] = True
    fake.rows["service_accounts"] = [{"id": "svc-1", "username": "service-account-crm"}]
    config = _config()
    config["collection"]["page_size"] = 1  # type: ignore[index]
    manifest = collect(config, tmp_path / "service.zip", fake)
    assert manifest["completeness"] == "full"
    calls = [call for call in fake.calls if call[0] == "service_accounts"]
    assert len(calls) == 1
    assert calls[0][1] == 0


class _Response:
    def __init__(self, payload: object) -> None:
        self.payload = payload

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self.payload).encode()


def test_http_client_refreshes_once_per_admin_request(monkeypatch) -> None:
    config = _config()
    monkeypatch.setenv("EARE_KEYCLOAK_SECRET_CANARY_DO_NOT_LEAK", "test-secret")
    monkeypatch.setattr(_HTTPClient, "_token", lambda _self: "t0")
    client = _HTTPClient(config)
    issued = iter(("t1", "t2"))
    monkeypatch.setattr(client, "_token", lambda: next(issued))
    requests: list[tuple[str, str]] = []

    def open_request(request: object) -> object:
        authorization = request.headers["Authorization"]  # type: ignore[attr-defined]
        requests.append((request.full_url, authorization))  # type: ignore[attr-defined]
        if len(requests) in {1, 3}:
            raise KeycloakError("expired", 401)
        return _Response([])

    monkeypatch.setattr(client, "_open", open_request)
    assert client._get("users", {"first": 0, "max": 1}) == []
    assert client._get("groups", {"first": 0, "max": 1}) == []
    assert [token for _, token in requests] == [
        "Bearer t0",
        "Bearer t1",
        "Bearer t1",
        "Bearer t2",
    ]


def test_http_client_fails_after_second_401(monkeypatch) -> None:
    config = _config()
    monkeypatch.setenv("EARE_KEYCLOAK_SECRET_CANARY_DO_NOT_LEAK", "test-secret")
    monkeypatch.setattr(_HTTPClient, "_token", lambda _self: "t0")
    client = _HTTPClient(config)
    monkeypatch.setattr(client, "_token", lambda: "t1")
    monkeypatch.setattr(
        client,
        "_open",
        lambda _request: (_ for _ in ()).throw(KeycloakError("expired", 401)),
    )
    try:
        client._get("users", {"first": 0, "max": 1})
    except KeycloakError as exc:
        assert exc.status_code == 401
    else:
        raise AssertionError("a second 401 was swallowed")
