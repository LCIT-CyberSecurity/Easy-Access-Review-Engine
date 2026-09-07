from __future__ import annotations

import argparse
from pathlib import Path

from access_review_engine.application import import_file_to_repository, load_classification_rules
from access_review_engine.importers.ad import import_ad_zip
from access_review_engine.importers.openldap import import_openldap_ldif
from access_review_engine.reporting import write_reports
from access_review_engine.storage import Repository


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="access-review")
    parser.add_argument("--db", default="access-review.db")
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate")
    validate.add_argument("file")

    imp = sub.add_parser("import")
    imp.add_argument("file")
    imp.add_argument("--provider", default="openldap")
    imp.add_argument("--classification-rules")

    sub.add_parser("findings-list")
    identities = sub.add_parser("identities-list")
    identities.add_argument("--provider")

    campaign_export = sub.add_parser("campaign-export")
    campaign_export.add_argument("output_dir")

    args = parser.parse_args(argv)
    repo = Repository(args.db)
    try:
        if args.command == "validate":
            _validate(Path(args.file))
            print("valid")
            return 0
        if args.command == "import":
            snapshot = import_file_to_repository(
                repo,
                args.file,
                provider_name=args.provider,
                classification_rules=load_classification_rules(args.classification_rules),
            )
            provider = snapshot.providers[0].name if snapshot.providers else args.provider
            print(f"imported provider={provider} snapshot={snapshot.id}")
            return 0
        if args.command == "findings-list":
            snapshots = repo.list_payloads("snapshots")
            for row in (snapshots[-1]["comparison_states"] if snapshots else []):
                if row["findings"] or row["classification"] != "expected_and_observed":
                    print(row)
            return 0
        if args.command == "identities-list":
            for row in repo.list_payloads("identities"):
                if not args.provider or row["provider"] == args.provider:
                    print(f"{row['provider']}/{row['identifier']} {row['type']} {row['status']}")
            return 0
        if args.command == "campaign-export":
            campaigns = repo.list_payloads("campaigns")
            if not campaigns:
                raise SystemExit("No campaign found")
            from access_review_engine.storage import hydrate_campaign, hydrate_decision, hydrate_review_item

            write_reports(
                args.output_dir,
                hydrate_campaign(campaigns[-1]),
                [hydrate_review_item(row) for row in repo.list_payloads("review_items")],
                [hydrate_decision(row) for row in repo.list_payloads("decisions")],
            )
            print(f"exported {args.output_dir}")
            return 0
    finally:
        repo.close()
    return 1


def _validate(path: Path) -> None:
    if path.suffix == ".zip":
        import_ad_zip(path)
    elif path.suffix.lower() in {".ldif", ".ldap"}:
        import_openldap_ldif(path)
    else:
        raise ValueError("Unsupported validation file type")


if __name__ == "__main__":
    raise SystemExit(main())
