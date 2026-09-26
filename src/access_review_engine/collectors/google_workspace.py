from __future__ import annotations

import argparse
import json
import os
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from zipfile import ZIP_DEFLATED, ZipFile

import yaml

from access_review_engine.google_artifacts import write_jsonl

MAX_RETRIES = 3
DEFAULT_TIMEOUT = 30


class WorkspaceClient(Protocol):
    def list(
        self, surface: str, page_token: str | None, page_size: int, group_id: str | None = None
    ) -> dict[str, Any]: ...


def _retry(
    call: Callable[[], dict[str, Any]], sleep: Callable[[float], None] = time.sleep
) -> dict[str, Any]:
    for attempt in range(MAX_RETRIES + 1):
        try:
            return call()
        except Exception as exc:
            status = getattr(exc, "status_code", getattr(exc, "status", None))
            if attempt >= MAX_RETRIES or status not in {429, 500, 502, 503, 504}:
                raise
            delay = getattr(exc, "retry_after", None) or min(8.0, 0.5 * (2**attempt))
            sleep(float(delay))
    raise AssertionError("unreachable")


def _response_key(surface: str) -> str:
    return {
        "users": "users",
        "groups": "groups",
        "memberships": "members",
        "admin_roles": "items",
        "admin_role_assignments": "items",
    }[surface]


def _collect_surface(
    client: WorkspaceClient, surface: str, page_size: int
) -> tuple[list[dict[str, Any]], int]:
    rows: list[dict[str, Any]] = []
    token: str | None = None
    pages = 0
    while True:
        response = _retry(lambda token=token: client.list(surface, token, page_size))
        pages += 1
        values = response.get(_response_key(surface), [])
        if not isinstance(values, list):
            raise ValueError(f"Workspace {surface} response items must be a list")
        rows.extend(value for value in values if isinstance(value, dict))
        token = response.get("nextPageToken")
        if not token:
            return rows, pages


def _collect_memberships(
    client: WorkspaceClient, groups: list[dict[str, Any]], page_size: int
) -> tuple[list[dict[str, Any]], int]:
    rows: list[dict[str, Any]] = []
    pages = 0
    for group in groups:
        group_id = str(group.get("id") or group.get("email") or "")
        token: str | None = None
        while True:
            response = _retry(
                lambda token=token, group_id=group_id: client.list(
                    "memberships", token, page_size, group_id
                )
            )
            pages += 1
            values = response.get("members", [])
            if not isinstance(values, list):
                raise ValueError("Workspace memberships response members must be a list")
            for member in values:
                if isinstance(member, dict):
                    rows.append(
                        {
                            "group_id": group.get("id"),
                            "group_email": group.get("email"),
                            "member_id": member.get("id"),
                            "member_email": member.get("email"),
                            "member_type": member.get("type"),
                            "role": member.get("role", "MEMBER"),
                        }
                    )
            token = response.get("nextPageToken")
            if not token:
                break
    return rows, pages


def collect(
    config: dict[str, Any], output: str | Path, client: WorkspaceClient | None = None
) -> dict[str, Any]:
    collection = config.get("collection") or {}
    requested = [name for name in ("users", "groups", "memberships") if collection.get(name, True)]
    if collection.get("admin_roles", False):
        requested.extend(("admin_roles", "admin_role_assignments"))
    elif collection.get("admin_role_assignments", False):
        requested.append("admin_role_assignments")
    if client is None:
        client = _build_client(config)
    if config.get("_check_only"):
        diagnostics: list[dict[str, str]] = [{"surface": "authentication", "status": "success"}]
        page_size = int(collection.get("page_size", 200))
        for surface in requested:
            try:
                if surface == "memberships":
                    groups, _ = _collect_surface(client, "groups", page_size)
                    if groups:
                        group_id = str(groups[0].get("id") or groups[0].get("email"))
                        _retry(
                            lambda group_id=group_id: client.list(
                                "memberships",
                                None,
                                page_size,
                                group_id,
                            )
                        )
                else:
                    _retry(lambda surface=surface: client.list(surface, None, page_size))
                diagnostics.append({"surface": surface, "status": "success"})
            except Exception as exc:
                diagnostics.append(
                    {"surface": surface, "status": "error", "error": type(exc).__name__}
                )
                if not collection.get("allow_partial", False):
                    raise RuntimeError(f"Workspace check failed for {surface}") from exc
        return {
            "source_type": "google_workspace",
            "provider": config["provider"],
            "check_only": True,
            "diagnostics": diagnostics,
            "completeness": "scoped",
        }
    started = datetime.now(UTC).isoformat()
    data: dict[str, list[dict[str, Any]]] = {}
    pages: dict[str, int] = {}
    errors: list[dict[str, str]] = []
    surface_files = {
        "users": "users.jsonl",
        "groups": "groups.jsonl",
        "memberships": "memberships.jsonl",
        "admin_roles": "admin-roles.jsonl",
        "admin_role_assignments": "admin-role-assignments.jsonl",
    }
    groups_for_memberships: list[dict[str, Any]] = []
    for surface in requested:
        try:
            if surface == "memberships":
                if not groups_for_memberships:
                    groups_for_memberships, _ = _collect_surface(
                        client, "groups", int(collection.get("page_size", 200))
                    )
                data[surface], pages[surface] = _collect_memberships(
                    client, groups_for_memberships, int(collection.get("page_size", 200))
                )
            else:
                data[surface], pages[surface] = _collect_surface(
                    client, surface, int(collection.get("page_size", 200))
                )
        except Exception as exc:
            errors.append({"surface": surface, "error": type(exc).__name__})
            data[surface] = []
            if not collection.get("allow_partial", False):
                raise RuntimeError(f"Workspace collection failed for {surface}") from exc
    completed = [
        surface for surface in requested if surface not in {row["surface"] for row in errors}
    ]
    completeness = "full" if not errors and set(completed) == set(requested) else "scoped"
    manifest = {
        "source_type": "google_workspace",
        "schema_version": 1,
        "provider": config["provider"],
        "customer_id": config["connection"]["customer_id"],
        "collector_version": "1",
        "started_at": started,
        "completed_at": datetime.now(UTC).isoformat(),
        "requested_surfaces": requested,
        "completed_surfaces": completed,
        "counts": {key: len(value) for key, value in data.items()},
        "pages": pages,
        "collection_errors": errors,
        "completeness": completeness,
        "authoritative_scope": {
            "connector_type": "google_workspace",
            "customer_id": str(config["connection"]["customer_id"]),
            "surfaces": sorted(requested),
        },
    }
    with ZipFile(output, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.yaml", yaml.safe_dump(manifest, sort_keys=False))
        for surface, name in surface_files.items():
            write_jsonl(zf, name, iter(data.get(surface, [])))
        zf.writestr("collection-errors.json", json.dumps(errors, sort_keys=True))
    return manifest


def _build_client(config: dict[str, Any]) -> WorkspaceClient:
    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build
    except ImportError as exc:
        raise RuntimeError("Google connector dependencies are not installed") from exc
    credentials_cfg = config.get("credentials") or {}
    env_name = credentials_cfg.get("service_account_file_env")
    if not isinstance(env_name, str) or not os.environ.get(env_name):
        raise RuntimeError("Workspace service account file environment variable is not configured")
    credential_path = Path(os.environ[env_name]).resolve()
    if not credential_path.is_file() or not os.access(credential_path, os.R_OK):
        raise RuntimeError("Workspace service account file is not readable")
    credentials = service_account.Credentials.from_service_account_file(
        str(credential_path),
        scopes=[
            "https://www.googleapis.com/auth/admin.directory.user.readonly",
            "https://www.googleapis.com/auth/admin.directory.group.readonly",
            "https://www.googleapis.com/auth/admin.directory.group.member.readonly",
            "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
        ],
    )
    credentials = credentials.with_subject(str(config["connection"]["delegated_admin"]))
    directory = build("admin", "directory_v1", credentials=credentials, cache_discovery=False)

    class Adapter:
        _groups: list[dict[str, Any]] | None = None

        def list(
            self, surface: str, page_token: str | None, page_size: int, group_id: str | None = None
        ) -> dict[str, Any]:
            kwargs = {"customer": config["connection"]["customer_id"], "maxResults": page_size}
            if page_token:
                kwargs["pageToken"] = page_token
            if surface == "users":
                return directory.users().list(**kwargs).execute(num_retries=0)
            if surface == "groups":
                return directory.groups().list(**kwargs).execute(num_retries=0)
            if surface == "memberships":
                return (
                    directory.members()
                    .list(
                        groupKey=group_id,
                        maxResults=page_size,
                        **({"pageToken": page_token} if page_token else {}),
                    )
                    .execute(num_retries=0)
                )
            if surface == "admin_roles":
                return directory.roles().list(**kwargs).execute(num_retries=0)
            return directory.roleAssignments().list(**kwargs).execute(num_retries=0)

    return Adapter()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    config = yaml.safe_load(Path(args.config).read_text(encoding="utf-8"))
    manifest = collect(config, args.output)
    if config.get("_check_only"):
        print(json.dumps(manifest, sort_keys=True))


if __name__ == "__main__":
    main()
