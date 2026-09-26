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
    def list(self, surface: str, page_token: str | None, page_size: int) -> dict[str, Any]: ...


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


def _collect_surface(
    client: WorkspaceClient, surface: str, page_size: int
) -> tuple[list[dict[str, Any]], int]:
    rows: list[dict[str, Any]] = []
    token: str | None = None
    pages = 0
    while True:
        response = _retry(lambda token=token: client.list(surface, token, page_size))
        pages += 1
        values = response.get("items") or response.get("resources") or []
        if not isinstance(values, list):
            raise ValueError(f"Workspace {surface} response items must be a list")
        rows.extend(value for value in values if isinstance(value, dict))
        token = response.get("nextPageToken")
        if not token:
            return rows, pages


def collect(
    config: dict[str, Any], output: str | Path, client: WorkspaceClient | None = None
) -> dict[str, Any]:
    collection = config.get("collection") or {}
    requested = [
        name
        for name in ("users", "groups", "memberships", "admin_roles", "admin_role_assignments")
        if collection.get(name, name != "admin_role_assignments")
    ]
    if client is None:
        client = _build_client(config)
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
    for surface in requested:
        try:
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
        "authoritative_scope": {"type": "providers", "values": [config["provider"]]},
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

        def list(self, surface: str, page_token: str | None, page_size: int) -> dict[str, Any]:
            kwargs = {"customer": config["connection"]["customer_id"], "maxResults": page_size}
            if page_token:
                kwargs["pageToken"] = page_token
            if surface == "users":
                return directory.users().list(**kwargs).execute(num_retries=0)
            if surface == "groups":
                return directory.groups().list(**kwargs).execute(num_retries=0)
            if surface == "memberships":
                if self._groups is None:
                    self._groups, _ = _collect_surface(self, "groups", page_size)
                values: list[dict[str, Any]] = []
                for group in self._groups:
                    group_key = group.get("id") or group.get("email")
                    members = (
                        directory.members()
                        .list(
                            groupKey=group_key,
                            maxResults=page_size,
                            **({"pageToken": page_token} if page_token else {}),
                        )
                        .execute(num_retries=0)
                    )
                    for member in members.get("members", []):
                        values.append(
                            {
                                "group_id": group.get("id"),
                                "group_email": group.get("email"),
                                "member_id": member.get("id"),
                                "member_email": member.get("email"),
                                "role": member.get("role", "MEMBER"),
                            }
                        )
                return {"items": values}
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
    collect(config, args.output)


if __name__ == "__main__":
    main()
