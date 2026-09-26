"""Defensive readers shared by the read-only Google collectors/importers."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path, PurePosixPath
from typing import Any
from zipfile import BadZipFile, ZipFile

import yaml

MAX_ARCHIVE_BYTES = 500_000_000
MAX_ENTRY_BYTES = 250_000_000
MAX_UNCOMPRESSED_BYTES = 1_500_000_000
MAX_RECORD_BYTES = 2_000_000


def read_artifact(
    path: str | Path, expected_source: str, files: set[str]
) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]]]:
    archive = Path(path)
    if archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("Import archive exceeds configured maximum size")
    try:
        with ZipFile(archive) as zf:
            infos = zf.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise ValueError("Archive contains duplicate filenames")
            if any(name.startswith("/") or ".." in PurePosixPath(name).parts for name in names):
                raise ValueError("Unsafe ZIP path detected")
            if set(names) - files - {"manifest.yaml"}:
                raise ValueError("Archive contains unexpected files")
            total = 0
            for info in infos:
                if info.file_size > MAX_ENTRY_BYTES:
                    raise ValueError("Archive member exceeds configured maximum size")
                total += info.file_size
            if total > MAX_UNCOMPRESSED_BYTES:
                raise ValueError("Archive uncompressed size exceeds configured maximum size")
            if "manifest.yaml" not in names:
                raise ValueError("Archive is missing required files: ['manifest.yaml']")
            manifest = yaml.safe_load(zf.read("manifest.yaml").decode("utf-8-sig"))
            if not isinstance(manifest, dict) or manifest.get("source_type") != expected_source:
                raise ValueError("Artifact manifest has an invalid source_type")
            provider = manifest.get("provider")
            if not isinstance(provider, str) or not provider.strip():
                raise ValueError("Artifact manifest must define provider")
            requested = manifest.get("requested_surfaces", [])
            completed = manifest.get("completed_surfaces", [])
            if (
                not isinstance(requested, list)
                or not isinstance(completed, list)
                or not set(completed).issubset(set(requested))
            ):
                raise ValueError("Artifact manifest has invalid surface completion data")
            surface_files = {
                "users": "users.jsonl",
                "groups": "groups.jsonl",
                "memberships": "memberships.jsonl",
                "admin_roles": "admin-roles.jsonl",
                "admin_role_assignments": "admin-role-assignments.jsonl",
                "iam_allow_policies": "iam-bindings.jsonl",
                "service_accounts": "service-accounts.jsonl",
            }
            required_names = {
                surface_files[surface] for surface in completed if surface in surface_files
            }
            missing = sorted(required_names - set(names))
            if manifest.get("completeness") == "full" and missing:
                raise ValueError(f"FULL artifact is missing completed surface files: {missing}")
            if manifest.get("completeness") == "full" and set(completed) != set(requested):
                raise ValueError("FULL artifact does not complete every requested surface")
            records: dict[str, list[dict[str, Any]]] = {}
            for name in files:
                if name not in names:
                    records[name] = []
                    continue
                if name == "collection-errors.json":
                    raw_errors = zf.read(name).decode("utf-8").strip()
                    value = json.loads(raw_errors) if raw_errors else []
                    if not isinstance(value, list) or not all(
                        isinstance(item, dict) for item in value
                    ):
                        raise ValueError("collection-errors.json must contain an array of objects")
                    records[name] = value
                    continue
                rows: list[dict[str, Any]] = []
                for raw in zf.read(name).splitlines():
                    if len(raw) > MAX_RECORD_BYTES:
                        raise ValueError("Artifact JSONL record is too large")
                    if not raw.strip():
                        continue
                    value = json.loads(raw.decode("utf-8"))
                    if not isinstance(value, dict):
                        raise ValueError(f"Artifact record in {name} must be an object")
                    rows.append(value)
                records[name] = rows
            counts = manifest.get("counts")
            if isinstance(counts, dict):
                count_keys = {
                    "users.jsonl": "users",
                    "groups.jsonl": "groups",
                    "memberships.jsonl": "memberships",
                    "admin-roles.jsonl": "admin_roles",
                    "admin-role-assignments.jsonl": "admin_role_assignments",
                    "iam-bindings.jsonl": "iam-bindings",
                    "service-accounts.jsonl": "service-accounts",
                }
                for filename, key in count_keys.items():
                    if (
                        key in counts
                        and filename in records
                        and int(counts[key]) != len(records[filename])
                    ):
                        raise ValueError(f"Artifact count mismatch for {key}")
            return manifest, records
    except BadZipFile as exc:
        raise ValueError("Invalid ZIP archive") from exc


def write_jsonl(zf: Any, name: str, rows: Iterator[dict[str, Any]]) -> int:
    import io

    buffer = io.BytesIO()
    count = 0
    for row in rows:
        buffer.write(json.dumps(row, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n")
        count += 1
    zf.writestr(name, buffer.getvalue())
    return count
