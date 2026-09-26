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


class GcpClient(Protocol):
    def list_bindings(self, scope: str, page_token: str | None) -> dict[str, Any]: ...
    def list_service_accounts(self, scope: str, page_token: str | None) -> dict[str, Any]: ...


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
            sleep(float(getattr(exc, "retry_after", None) or min(8.0, 0.5 * (2**attempt))))
    raise AssertionError("unreachable")


def _pages(call: Callable[[str | None], dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    rows: list[dict[str, Any]] = []
    token: str | None = None
    count = 0
    while True:
        response = _retry(lambda token=token: call(token))
        count += 1
        values = (
            response.get("bindings")
            or response.get("resources")
            or response.get("serviceAccounts")
            or []
        )
        rows.extend(row for row in values if isinstance(row, dict))
        token = response.get("nextPageToken")
        if not token:
            return rows, count


def collect(
    config: dict[str, Any], output: str | Path, client: GcpClient | None = None
) -> dict[str, Any]:
    if client is None:
        client = _build_client(config)
    scope = str(config["connection"]["scope"])
    collection = config.get("collection") or {}
    errors: list[dict[str, str]] = []
    pages: dict[str, int] = {}
    try:
        bindings, pages["iam_allow_policies"] = _pages(
            lambda token: client.list_bindings(scope, token)
        )
    except Exception as exc:
        errors.append({"surface": "iam_allow_policies", "error": type(exc).__name__})
        bindings = []
        if not collection.get("allow_partial", False):
            raise RuntimeError("GCP IAM collection failed") from exc
    try:
        accounts, pages["service_accounts"] = _pages(
            lambda token: client.list_service_accounts(scope, token)
        )
    except Exception as exc:
        errors.append({"surface": "service_accounts", "error": type(exc).__name__})
        accounts = []
        if not collection.get("allow_partial", False):
            raise RuntimeError("GCP service account collection failed") from exc
    requested = [
        name
        for name, enabled in (
            ("iam_allow_policies", collection.get("iam_allow_policies", True)),
            ("service_accounts", collection.get("service_accounts", True)),
        )
        if enabled
    ]
    completed = [
        name for name in requested if not any(error["surface"] == name for error in errors)
    ]
    manifest = {
        "source_type": "gcp_iam",
        "schema_version": 1,
        "provider": config["provider"],
        "scope": scope,
        "collector_version": "1",
        "started_at": datetime.now(UTC).isoformat(),
        "completed_at": datetime.now(UTC).isoformat(),
        "requested_surfaces": requested,
        "completed_surfaces": completed,
        "counts": {"iam-bindings": len(bindings), "service-accounts": len(accounts)},
        "pages": pages,
        "collection_errors": errors,
        "completeness": "full" if not errors and set(requested) == set(completed) else "scoped",
        "authoritative_scope": {"type": "providers", "values": [config["provider"]]},
    }
    with ZipFile(output, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.yaml", yaml.safe_dump(manifest, sort_keys=False))
        write_jsonl(zf, "iam-bindings.jsonl", iter(bindings))
        write_jsonl(zf, "service-accounts.jsonl", iter(accounts))
        write_jsonl(zf, "resource-hierarchy.jsonl", iter(()))
        zf.writestr("collection-errors.json", json.dumps(errors, sort_keys=True))
    return manifest


def _build_client(config: dict[str, Any]) -> GcpClient:
    try:
        import google.auth
        from google.oauth2 import service_account
        from googleapiclient.discovery import build
    except ImportError as exc:
        raise RuntimeError("Google connector dependencies are not installed") from exc
    credential_cfg = config.get("credentials") or {}
    env_name = credential_cfg.get("service_account_file_env")
    if env_name:
        if (
            not isinstance(env_name, str)
            or not os.environ.get(env_name)
            or not Path(os.environ[env_name]).is_file()
        ):
            raise RuntimeError("GCP service account file is not configured or readable")
        credentials = service_account.Credentials.from_service_account_file(
            os.environ[env_name],
            scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"],
        )
    else:
        credentials, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"]
        )
    asset = build("cloudasset", "v1", credentials=credentials, cache_discovery=False)
    iam = build("iam", "v1", credentials=credentials, cache_discovery=False)

    class Adapter:
        def list_bindings(self, scope: str, page_token: str | None) -> dict[str, Any]:
            kwargs = {"scope": scope, "query": "policy:"}
            if page_token:
                kwargs["pageToken"] = page_token
            return asset.v1().searchAllIamPolicies(**kwargs).execute(num_retries=0)

        def list_service_accounts(self, scope: str, page_token: str | None) -> dict[str, Any]:
            project = scope.removeprefix("projects/")
            kwargs = {"name": f"projects/{project}"}
            if page_token:
                kwargs["pageToken"] = page_token
            return iam.projects().serviceAccounts().list(**kwargs).execute(num_retries=0)

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
