#!/usr/bin/env python3
"""Build a guarded, deterministic Google lab mutation plan.

This script is deliberately separate from the production collectors.  The default
mode is plan-only; applying a plan requires an explicit lab marker and target.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import yaml


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True)
    parser.add_argument("--source", choices=("workspace", "gcp", "all"), default="all")
    parser.add_argument("--customer-id")
    parser.add_argument("--project")
    parser.add_argument("--marker", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--allow-production-looking-target", action="store_true")
    args = parser.parse_args()
    spec = yaml.safe_load(Path(args.spec).read_text(encoding="utf-8")) or {}
    if args.marker != "EARE-GOOGLE-LAB":
        raise SystemExit("Refusing: --marker must be EARE-GOOGLE-LAB")
    if args.apply and not args.allow_production_looking_target and (args.customer_id or args.project):
        target = f"{args.customer_id or ''} {args.project or ''}".casefold()
        if any(word in target for word in ("prod", "production", "live")):
            raise SystemExit("Refusing a production-looking target without explicit override")
    operations: list[dict[str, object]] = []
    if args.source in {"workspace", "all"}:
        workspace = spec.get("workspace") or {}
        operations.append({"provider": "google_workspace", "target": args.customer_id, "users": workspace.get("users", []), "groups": workspace.get("groups", []), "memberships": workspace.get("memberships", []), "admin_roles": workspace.get("admin_roles", [])})
    if args.source in {"gcp", "all"}:
        gcp = spec.get("gcp") or {}
        operations.append({"provider": "gcp_iam", "target": args.project or gcp.get("project"), "bindings": gcp.get("bindings", []), "service_accounts": gcp.get("service_accounts", [])})
    print(yaml.safe_dump({"mode": "apply" if args.apply else "plan", "marker": args.marker, "operations": operations}, sort_keys=False))
    if args.apply:
        raise SystemExit("Apply mode is intentionally gated: connect this lab-only plan to an approved tenant-specific mutator")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
