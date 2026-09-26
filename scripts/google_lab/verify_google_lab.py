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
    args = parser.parse_args()
    spec = yaml.safe_load(Path(args.spec).read_text(encoding="utf-8")) or {}
    artifact = Path(args.artifact)
    source = "gcp_iam" if "gcp" in spec else "google_workspace"
    files = {"users.jsonl", "groups.jsonl", "memberships.jsonl", "admin-roles.jsonl", "admin-role-assignments.jsonl", "iam-bindings.jsonl", "service-accounts.jsonl", "resource-hierarchy.jsonl", "collection-errors.json"}
    manifest, records = read_artifact(artifact, source, files)
    expected = spec.get("gcp" if source == "gcp_iam" else "workspace", {})
    checks = {key: len(records.get(filename, [])) for key, filename in {"users": "users.jsonl", "groups": "groups.jsonl", "memberships": "memberships.jsonl", "admin_roles": "admin-roles.jsonl", "bindings": "iam-bindings.jsonl", "service_accounts": "service-accounts.jsonl"}.items() if key in expected}
    failures = [f"{key}: expected {len(expected[key])}, got {value}" for key, value in checks.items() if isinstance(expected.get(key), list) and len(expected[key]) != value]
    print(f"source={manifest['source_type']} provider={manifest['provider']} completeness={manifest.get('completeness')}")
    for failure in failures: print(f"DIFF {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
