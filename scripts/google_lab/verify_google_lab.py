#!/usr/bin/env python3
"""Compare a collected Google artifact with a non-secret lab specification."""

from __future__ import annotations

import argparse
from pathlib import Path

import yaml

from access_review_engine.google_artifacts import read_artifact


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--spec", required=True)
    parser.add_argument("--source", choices=("workspace", "gcp"), required=True)
    args = parser.parse_args()
    spec = yaml.safe_load(Path(args.spec).read_text(encoding="utf-8")) or {}
    artifact = Path(args.artifact)
    source = "gcp_iam" if args.source == "gcp" else "google_workspace"
    files = {
        "users.jsonl",
        "groups.jsonl",
        "memberships.jsonl",
        "admin-roles.jsonl",
        "admin-role-assignments.jsonl",
        "iam-bindings.jsonl",
        "service-accounts.jsonl",
        "resource-hierarchy.jsonl",
        "collection-errors.json",
    }
    manifest, records = read_artifact(artifact, source, files)
    expected = spec.get("gcp" if source == "gcp_iam" else "workspace", {})
    checks = {
        key: len(records.get(filename, []))
        for key, filename in {
            "users": "users.jsonl",
            "groups": "groups.jsonl",
            "memberships": "memberships.jsonl",
            "admin_roles": "admin-roles.jsonl",
            "bindings": "iam-bindings.jsonl",
            "service_accounts": "service-accounts.jsonl",
        }.items()
        if key in expected
    }
    failures = [
        f"{key}: expected {len(expected[key])}, got {value}"
        for key, value in checks.items()
        if isinstance(expected.get(key), list) and len(expected[key]) != value
    ]

    def tuples(key: str) -> set[tuple[str, ...]]:
        if key == "users":
            return {
                (
                    str(row.get("primaryEmail") or row.get("email") or "").lower(),
                    str(row.get("id") or row.get("native_id") or ""),
                )
                for row in records.get("users.jsonl", [])
            }
        if key == "groups":
            return {
                (
                    str(row.get("email") or "").lower(),
                    str(row.get("id") or row.get("native_id") or ""),
                )
                for row in records.get("groups.jsonl", [])
            }
        if key == "memberships":
            return {
                (
                    str(row.get("group_id") or ""),
                    str(row.get("member_id") or ""),
                    str(row.get("role") or "").upper(),
                )
                for row in records.get("memberships.jsonl", [])
            }
        if key == "bindings":
            return {
                (
                    str(row.get("resource") or ""),
                    str(row.get("role") or ""),
                    str(
                        (row.get("condition") or {}).get("expression", "")
                        if isinstance(row.get("condition"), dict)
                        else row.get("condition") or ""
                    ),
                    ",".join(sorted(str(item) for item in row.get("members", []))),
                )
                for row in records.get("iam-bindings.jsonl", [])
            }
        if key == "service_accounts":
            return {
                (
                    str(row.get("email") or row.get("name") or "").lower(),
                    str(row.get("uniqueId") or row.get("unique_id") or ""),
                )
                for row in records.get("service-accounts.jsonl", [])
            }
        return set()

    def expected_tuples(key: str) -> set[tuple[str, ...]]:
        values = expected.get(key, [])
        if not isinstance(values, list):
            return set()
        if key == "users":
            return {
                (
                    str(row.get("primaryEmail") or row.get("email") or "").lower(),
                    str(row.get("id") or row.get("native_id") or ""),
                )
                for row in values
                if isinstance(row, dict)
            }
        if key == "groups":
            return {
                (
                    str(row.get("email") or "").lower(),
                    str(row.get("id") or row.get("native_id") or ""),
                )
                for row in values
                if isinstance(row, dict)
            }
        if key == "memberships":
            return {
                (
                    str(row.get("group_id") or ""),
                    str(row.get("member_id") or ""),
                    str(row.get("role") or "").upper(),
                )
                for row in values
                if isinstance(row, dict)
            }
        if key == "bindings":
            return {
                (
                    str(row.get("resource") or ""),
                    str(row.get("role") or ""),
                    str(
                        (row.get("condition") or {}).get("expression", "")
                        if isinstance(row.get("condition"), dict)
                        else row.get("condition") or ""
                    ),
                    ",".join(sorted(str(item) for item in row.get("members", []))),
                )
                for row in values
                if isinstance(row, dict)
            }
        if key == "service_accounts":
            return {
                (
                    str(row.get("email") or row.get("name") or "").lower(),
                    str(row.get("uniqueId") or row.get("unique_id") or ""),
                )
                for row in values
                if isinstance(row, dict)
            }
        return set()

    for key in ("users", "groups", "memberships", "bindings", "service_accounts"):
        if (
            isinstance(expected.get(key), list)
            and expected[key]
            and isinstance(expected[key][0], dict)
        ):
            if expected_tuples(key) != tuples(key):
                failures.append(f"{key}: stable object mismatch")
    print(
        f"source={manifest['source_type']} provider={manifest['provider']} "
        f"completeness={manifest.get('completeness')}"
    )
    for failure in failures:
        print(f"DIFF {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
