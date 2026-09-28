"""Read-only Keycloak Admin REST collector.

The collector deliberately emits the V0 artifact contract.  It does not
compute effective permissions; that remains the responsibility of the EARE
normalizer and graph engine.
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from zipfile import ZIP_DEFLATED, ZipFile

import yaml

from access_review_engine.google_artifacts import write_jsonl
from access_review_engine.importers.keycloak import KEYCLOAK_V1_REQUIRED_SURFACES

MAX_RETRIES = 3
SURFACE_FILES = {
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
}


class KeycloakError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.retryable = status_code is None


class KeycloakClient(Protocol):
    def list(
        self, surface: str, page: int, page_size: int, **kwargs: Any
    ) -> list[dict[str, Any]]: ...

    def related(
        self, surface: str, parent: dict[str, Any], **kwargs: Any
    ) -> list[dict[str, Any]]: ...

    def check_realm(self) -> None: ...


def _retry(
    call: Callable[[], list[dict[str, Any]]], sleep: Callable[[float], None] = time.sleep
) -> list[dict[str, Any]]:
    for attempt in range(MAX_RETRIES + 1):
        try:
            return call()
        except Exception as exc:
            status = getattr(exc, "status_code", getattr(exc, "status", None))
            transient_status = status in {429, 502, 503, 504}
            retryable = transient_status or getattr(exc, "retryable", False)
            if attempt >= MAX_RETRIES or not retryable:
                raise
            delay = getattr(exc, "retry_after", None) or min(8.0, 0.5 * (2**attempt))
            sleep(float(delay))
    raise AssertionError("unreachable")


def _pages(
    collector: KeycloakClient, surface: str, page_size: int, **kwargs: Any
) -> tuple[list[dict[str, Any]], int]:
    rows: list[dict[str, Any]] = []
    page = 0
    while True:
        values = _retry(lambda page=page: collector.list(surface, page, page_size, **kwargs))
        page += 1
        rows.extend(values)
        if len(values) < page_size:
            return rows, page


def _stable(value: Any) -> str:
    return str(value or "").strip()


def _role_row(
    role: dict[str, Any], kind: str, client: dict[str, Any] | None = None
) -> dict[str, Any]:
    row = dict(role)
    row["role_kind"] = kind
    row["id"] = _stable(role.get("id"))
    if kind == "client":
        row["client_id"] = _stable(client.get("id") if client else role.get("client_id"))
        row["clientId"] = _stable(client.get("clientId") if client else role.get("clientId"))
    return row


def collect(
    config: dict[str, Any], output: str | Path, client: KeycloakClient | None = None
) -> dict[str, Any]:
    connection = config.get("connection") or {}
    collection = config.get("collection") or {}
    page_size = int(collection.get("page_size", 100))
    if page_size <= 0:
        raise ValueError("Keycloak collection.page_size must be positive")
    requested = [surface for surface in SURFACE_FILES if collection.get(surface, True)]
    if client is None:
        client = _build_client(config)
    if config.get("_check_only"):
        diagnostics: list[dict[str, str]] = []
        try:
            check_realm = getattr(client, "check_realm", None)
            if check_realm is not None:
                check_realm()
            diagnostics.append({"surface": "authentication", "status": "success"})
        except Exception as exc:
            diagnostics.append(
                {"surface": "authentication", "status": "error", "error": type(exc).__name__}
            )
            raise RuntimeError("Keycloak authentication or realm check failed") from exc
        probes = ("users", "groups", "clients", "realm_roles")
        for surface in (surface for surface in requested if surface in probes):
            try:
                _pages(client, surface, page_size)
                diagnostics.append({"surface": surface, "status": "success"})
            except Exception as exc:
                diagnostics.append(
                    {"surface": surface, "status": "error", "error": type(exc).__name__}
                )
                if not collection.get("allow_partial", False):
                    raise RuntimeError(f"Keycloak check failed for {surface}") from exc
        try:
            clients = _pages(client, "clients", 1)[0] if "clients" in requested else []
            groups = _pages(client, "groups", 1)[0] if "groups" in requested else []
            users = _pages(client, "users", 1)[0] if "users" in requested else []
            dependent_checks = []
            if groups:
                dependent_checks.append(("memberships", {"group": groups[0]}))
            if clients:
                if clients[0].get("serviceAccountsEnabled"):
                    dependent_checks.append(("service_accounts", {"client": clients[0]}))
                dependent_checks.append(("client_roles", {"client": clients[0]}))
            if users:
                dependent_checks.append(("user_role_mappings", {"subject": users[0]}))
            if groups:
                dependent_checks.append(("group_role_mappings", {"subject": groups[0]}))
            for surface, kwargs in dependent_checks:
                _retry(
                    lambda surface=surface, kwargs=kwargs: client.list(
                        surface, 0, page_size, **kwargs
                    )
                )
            diagnostics.append({"surface": "dependent_surfaces", "status": "success"})
        except Exception as exc:
            diagnostics.append(
                {"surface": "dependent_surfaces", "status": "error", "error": type(exc).__name__}
            )
            if not collection.get("allow_partial", False):
                raise RuntimeError("Keycloak dependent surface check failed") from exc
        return {
            "source_type": "keycloak",
            "provider": config["provider"],
            "realm": connection["realm"],
            "check_only": True,
            "diagnostics": diagnostics,
            "completeness": "scoped",
        }

    started = datetime.now(UTC).isoformat()
    data: dict[str, list[dict[str, Any]]] = {surface: [] for surface in requested}
    pages: dict[str, int] = {}
    errors: list[dict[str, str]] = []
    failed_surfaces: set[str] = set()

    def run(surface: str, fn: Callable[[], tuple[list[dict[str, Any]], int]]) -> None:
        try:
            data[surface], pages[surface] = fn()
        except Exception as exc:
            errors.append({"surface": surface, "error": type(exc).__name__})
            failed_surfaces.add(surface)
            data[surface] = []
            if not collection.get("allow_partial", False):
                raise RuntimeError(f"Keycloak collection failed for {surface}") from exc

    if "users" in requested:
        run("users", lambda: _pages(client, "users", page_size))
    if "groups" in requested:
        try:
            raw_groups, group_pages = _pages(client, "groups", page_size)
        except Exception as exc:
            errors.append({"surface": "groups", "error": type(exc).__name__})
            failed_surfaces.add("groups")
            if not collection.get("allow_partial", False):
                raise RuntimeError("Keycloak collection failed for groups") from exc
            raw_groups, group_pages = [], 0
        flat: list[dict[str, Any]] = []
        nested: list[dict[str, Any]] = []

        def flatten(group: dict[str, Any], parent_id: str | None = None) -> None:
            row = {key: value for key, value in group.items() if key != "subGroups"}
            row["id"] = _stable(group.get("id"))
            flat.append(row)
            if parent_id:
                nested.append(
                    {
                        "id": f"group:{row['id']}:{parent_id}",
                        "member_id": row["id"],
                        "group_id": parent_id,
                        "membership_type": "nested_group",
                    }
                )
            for child in group.get("subGroups", []) or []:
                if isinstance(child, dict):
                    flatten(child, row["id"])

        for group in raw_groups:
            flatten(group)
        data["groups"], pages["groups"] = flat, group_pages
        if "memberships" in requested:
            memberships: list[dict[str, Any]] = list(nested)
            membership_pages = 0
            try:
                for group in flat:
                    members, count = _pages(client, "memberships", page_size, group=group)
                    membership_pages += count
                    memberships.extend(
                        {
                            "id": f"membership:{_stable(member.get('id'))}:{group['id']}",
                            "member_id": _stable(member.get("id")),
                            "group_id": group["id"],
                            "membership_type": "direct",
                        }
                        for member in members
                    )
            except Exception as exc:
                errors.append({"surface": "memberships", "error": type(exc).__name__})
                failed_surfaces.add("memberships")
                if not collection.get("allow_partial", False):
                    raise RuntimeError("Keycloak collection failed for memberships") from exc
            if "groups" in failed_surfaces:
                errors.append({"surface": "memberships", "error": "dependency_failed:groups"})
                failed_surfaces.add("memberships")
                memberships, membership_pages = [], 0
            data["memberships"], pages["memberships"] = memberships, membership_pages
    elif "memberships" in requested:
        errors.append({"surface": "memberships", "error": "dependency_failed:groups"})
        failed_surfaces.add("memberships")
        data["memberships"], pages["memberships"] = [], 0

    clients: list[dict[str, Any]] = []
    clients_ok = True
    if "clients" in requested or "client_roles" in requested or "service_accounts" in requested:
        try:
            clients, client_pages = _pages(client, "clients", page_size)
        except Exception as exc:
            clients_ok = False
            failed_surfaces.add("clients")
            errors.append({"surface": "clients", "error": type(exc).__name__})
            clients, client_pages = [], 0
            if not collection.get("allow_partial", False):
                raise RuntimeError("Keycloak collection failed for clients") from exc
        if "clients" in requested:
            data["clients"], pages["clients"] = clients, client_pages
    if "realm_roles" in requested:
        run("realm_roles", lambda: _pages(client, "realm_roles", page_size))
    if "client_roles" in requested:
        client_roles: list[dict[str, Any]] = []
        role_pages = 0
        if not clients_ok:
            errors.append({"surface": "client_roles", "error": "dependency_failed:clients"})
            failed_surfaces.add("client_roles")
        else:
            try:
                for item in clients:
                    roles, count = _pages(client, "client_roles", page_size, client=item)
                    role_pages += count
                    client_roles.extend(_role_row(role, "client", item) for role in roles)
            except Exception as exc:
                errors.append({"surface": "client_roles", "error": type(exc).__name__})
                failed_surfaces.add("client_roles")
                if not collection.get("allow_partial", False):
                    raise RuntimeError("Keycloak collection failed for client_roles") from exc
        data["client_roles"], pages["client_roles"] = client_roles, role_pages
    for surface, subject_key in (("user_role_mappings", "user"), ("group_role_mappings", "group")):
        if surface in requested:
            parent_surface = "users" if subject_key == "user" else "groups"
            subjects = data.get(parent_surface, [])
            mappings: list[dict[str, Any]] = []
            mapping_pages = 0
            if parent_surface not in requested or parent_surface in failed_surfaces:
                errors.append({"surface": surface, "error": f"dependency_failed:{parent_surface}"})
                failed_surfaces.add(surface)
            else:
                try:
                    for subject in subjects:
                        values, count = _pages(client, surface, page_size, subject=subject)
                        mapping_pages += count
                        mappings.extend(values)
                except Exception as exc:
                    errors.append({"surface": surface, "error": type(exc).__name__})
                    failed_surfaces.add(surface)
                    if not collection.get("allow_partial", False):
                        raise RuntimeError(f"Keycloak collection failed for {surface}") from exc
            data[surface], pages[surface] = mappings, mapping_pages
    if "composite_roles" in requested:
        composites: list[dict[str, Any]] = []
        composite_pages = 0
        roles = [(role, "realm", None) for role in data.get("realm_roles", [])] + [
            (
                role,
                "client",
                next(
                    (
                        item
                        for item in clients
                        if _stable(item.get("id")) == _stable(role.get("client_id"))
                    ),
                    None,
                ),
            )
            for role in data.get("client_roles", [])
        ]
        if (
            "realm_roles" not in requested
            or "client_roles" not in requested
            or "realm_roles" in failed_surfaces
            or "client_roles" in failed_surfaces
        ):
            errors.append({"surface": "composite_roles", "error": "dependency_failed:roles"})
            failed_surfaces.add("composite_roles")
        if "composite_roles" not in failed_surfaces:
            for role, kind, owner in roles:
                if not role.get("composite"):
                    continue
                try:
                    children, count = _pages(
                        client, "composites", page_size, role=role, role_kind=kind, client=owner
                    )
                    composite_pages += count
                    for child in children:
                        child_kind = "client" if child.get("clientRole") else "realm"
                        composites.append(
                            {
                                "id": (
                                    f"composite:{kind}:{role.get('id')}:{child_kind}:{child.get('id')}"
                                ),
                                "parent_kind": kind,
                                "parent_role_id": _stable(role.get("id")),
                                "parent_client_id": _stable(owner.get("id")) if owner else "",
                                "child_kind": child_kind,
                                "child_role_id": _stable(child.get("id")),
                                "child_client_id": _stable(
                                    (child.get("containerId") or child.get("client_id"))
                                    if child_kind == "client"
                                    else ""
                                ),
                            }
                        )
                except Exception as exc:
                    errors.append({"surface": "composite_roles", "error": type(exc).__name__})
                    failed_surfaces.add("composite_roles")
                    if not collection.get("allow_partial", False):
                        raise RuntimeError(
                            "Keycloak collection failed for composite_roles"
                        ) from exc
        data["composite_roles"], pages["composite_roles"] = composites, composite_pages
    if "service_accounts" in requested:
        service_rows: list[dict[str, Any]] = []
        service_pages = 0
        if "clients" not in requested or not clients_ok:
            errors.append({"surface": "service_accounts", "error": "dependency_failed:clients"})
            failed_surfaces.add("service_accounts")
        else:
            try:
                for item in clients:
                    if not item.get("serviceAccountsEnabled", False):
                        continue
                    values = _retry(
                        lambda item=item: client.list("service_accounts", 0, page_size, client=item)
                    )
                    service_pages += 1
                    service_rows.extend(
                        {
                            **row,
                            "client_id": _stable(item.get("id")),
                            "clientId": _stable(item.get("clientId")),
                            "service_account": True,
                        }
                        for row in values
                    )
            except Exception as exc:
                errors.append({"surface": "service_accounts", "error": type(exc).__name__})
                failed_surfaces.add("service_accounts")
                if not collection.get("allow_partial", False):
                    raise RuntimeError("Keycloak collection failed for service_accounts") from exc
        data["service_accounts"], pages["service_accounts"] = service_rows, service_pages

    completed = [
        surface for surface in requested if not any(error["surface"] == surface for error in errors)
    ]
    completeness = (
        "full" if not errors and set(requested) == KEYCLOAK_V1_REQUIRED_SURFACES else "scoped"
    )
    manifest = {
        "source_type": "keycloak",
        "schema_version": 1,
        "provider": config["provider"],
        "realm": connection["realm"],
        "base_url": connection.get("base_url"),
        "collector_version": "1",
        "started_at": started,
        "completed_at": datetime.now(UTC).isoformat(),
        "requested_surfaces": requested,
        "completed_surfaces": completed,
        "counts": {surface: len(data.get(surface, [])) for surface in requested},
        "pages": pages,
        "collection_errors": errors,
        "completeness": completeness,
        "authoritative_scope": {
            "connector_type": "keycloak",
            "realm": str(connection["realm"]),
            "surfaces": sorted(requested),
        },
    }
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        archive.writestr("manifest.yaml", yaml.safe_dump(manifest, sort_keys=False))
        for surface, filename in SURFACE_FILES.items():
            write_jsonl(archive, filename, iter(data.get(surface, [])))
        archive.writestr("collection-errors.json", json.dumps(errors, sort_keys=True))
    return manifest


class _HTTPClient:
    def __init__(self, config: dict[str, Any]) -> None:
        connection = config["connection"]
        self.base = str(connection["base_url"]).rstrip("/")
        if not self.base.lower().startswith(("https://", "http://")):
            raise ValueError("Keycloak base_url must use http:// or https://")
        self.realm = str(connection["realm"])
        self.timeout = float((config.get("collection") or {}).get("timeout", 30))
        credentials = config.get("credentials") or {}
        env_name = credentials.get("client_secret_env")
        if not isinstance(env_name, str) or not os.environ.get(env_name):
            raise RuntimeError("Keycloak client secret environment variable is not configured")
        self.secret = os.environ[env_name]
        self.client_id = str(connection["client_id"])
        self.token = self._token()

    def _open(self, request: urllib.request.Request) -> Any:
        context = ssl.create_default_context()
        try:
            # The base URL is validated as http(s) before any request is built.
            return urllib.request.urlopen(request, timeout=self.timeout, context=context)  # noqa: S310
        except urllib.error.HTTPError as exc:
            raise KeycloakError(f"Keycloak API returned HTTP {exc.code}", exc.code) from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise KeycloakError(f"Keycloak API connection failed: {type(exc).__name__}") from None

    def _token(self) -> str:
        url = (
            f"{self.base}/realms/{urllib.parse.quote(self.realm, safe='')}"
            "/protocol/openid-connect/token"
        )
        body = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.secret,
            }
        ).encode()
        with self._open(
            urllib.request.Request(  # noqa: S310
                url,
                data=body,
                method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        ) as response:
            value = json.loads(response.read())
        token = value.get("access_token")
        if not isinstance(token, str) or not token:
            raise KeycloakError("Keycloak token response did not contain an access token")
        return token

    def _get(self, path: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        query = urllib.parse.urlencode(
            {key: value for key, value in params.items() if value is not None}
        )
        request = urllib.request.Request(  # noqa: S310
            f"{self.base}/admin/realms/{urllib.parse.quote(self.realm, safe='')}/{path}?{query}",
            headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json"},
            method="GET",
        )
        for attempt in range(2):
            try:
                with self._open(request) as response:
                    value = json.loads(response.read())
                break
            except KeycloakError as exc:
                if exc.status_code != 401 or attempt:
                    raise
                self.token = self._token()
                request = urllib.request.Request(  # noqa: S310
                    f"{self.base}/admin/realms/{urllib.parse.quote(self.realm, safe='')}"
                    f"/{path}?{query}",
                    headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json"},
                    method="GET",
                )
        return value if isinstance(value, list) else [value] if isinstance(value, dict) else []

    def check_realm(self) -> None:
        self._get("", {})

    def list(self, surface: str, page: int, page_size: int, **kwargs: Any) -> list[dict[str, Any]]:
        first = page * page_size
        if surface == "users":
            return self._get("users", {"first": first, "max": page_size})
        if surface == "groups":
            return self._get("groups", {"first": first, "max": page_size})
        if surface == "clients":
            return self._get("clients", {"first": first, "max": page_size})
        if surface == "realm_roles":
            return self._get("roles", {"first": first, "max": page_size})
        if surface == "memberships":
            return self._get(
                f"groups/{urllib.parse.quote(kwargs['group']['id'], safe='')}/members",
                {"first": first, "max": page_size},
            )
        if surface == "client_roles":
            return self._get(
                f"clients/{urllib.parse.quote(kwargs['client']['id'], safe='')}/roles",
                {"first": first, "max": page_size},
            )
        if surface in {"user_role_mappings", "group_role_mappings"}:
            subject = kwargs["subject"]
            prefix = "users" if surface == "user_role_mappings" else "groups"
            value = self._get(
                f"{prefix}/{urllib.parse.quote(subject['id'], safe='')}/role-mappings", {}
            )
            rows: list[dict[str, Any]] = []
            for role in (
                value[0].get("realmMappings", []) if value and isinstance(value[0], dict) else []
            ):
                rows.append(
                    {
                        **role,
                        "role_id": role.get("id"),
                        "id": f"{prefix[:-1]}-role-mapping:{subject['id']}:realm:{role.get('id')}",
                        "role_kind": "realm",
                        ("user_id" if prefix == "users" else "group_id"): subject["id"],
                    }
                )
            for client_id, mapping in (
                value[0].get("clientMappings", {}) if value and isinstance(value[0], dict) else {}
            ).items():
                native_client_id = _stable(
                    mapping.get("id") or mapping.get("containerId") or client_id
                )
                for role in mapping.get("mappings", []):
                    rows.append(
                        {
                            **role,
                            "role_id": role.get("id"),
                            "id": (
                                f"{prefix[:-1]}-role-mapping:{subject['id']}:client:"
                                f"{native_client_id}:{role.get('id')}"
                            ),
                            "role_kind": "client",
                            "client_id": native_client_id,
                            "clientId": mapping.get("clientId"),
                            ("user_id" if prefix == "users" else "group_id"): subject["id"],
                        }
                    )
            return rows[page * page_size : (page + 1) * page_size]
        if surface == "service_accounts":
            return self._get(
                "clients/"
                f"{urllib.parse.quote(kwargs['client']['id'], safe='')}/service-account-user",
                {},
            )
        if surface == "composites":
            role = kwargs["role"]
            role_id = _stable(role.get("id"))
            if not role_id:
                raise KeycloakError("Keycloak composite role is missing its native id")
            prefix = f"roles-by-id/{urllib.parse.quote(role_id, safe='')}/composites"
            return self._get(prefix, {"first": first, "max": page_size})
        raise ValueError(f"Unsupported Keycloak surface: {surface}")


def _build_client(config: dict[str, Any]) -> KeycloakClient:
    return _HTTPClient(config)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    config = yaml.safe_load(Path(args.config).read_text(encoding="utf-8"))
    result = collect(config, args.output)
    if config.get("_check_only"):
        print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
