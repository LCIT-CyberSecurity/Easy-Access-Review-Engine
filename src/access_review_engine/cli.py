from __future__ import annotations

import argparse
from pathlib import Path

from access_review_engine.application import import_file_to_repository, load_classification_rules, _zip_source_type
from access_review_engine.importers.ad import import_ad_zip
from access_review_engine.importers.openldap import import_openldap_ldif, import_openldap_zip
from access_review_engine.reporting import write_reports
from access_review_engine.services import calculate_effective_accesses
from access_review_engine.storage import (
    Repository,
    hydrate_access,
    hydrate_access_relation,
    hydrate_assignment,
)


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

    effective = sub.add_parser("access-effective")
    effective.add_argument("identity")
    effective.add_argument("--provider")

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
            imports = repo.list_payloads("imports")
            if imports and imports[-1].get("completeness") != "full":
                print({"finding": "collection_incomplete", "import_id": imports[-1]["id"], "provider": imports[-1]["provider"]})
            return 0
        if args.command == "identities-list":
            for row in repo.list_payloads("identities"):
                if not args.provider or row["provider"] == args.provider:
                    print(f"{row['provider']}/{row['identifier']} {row['type']} {row['status']}")
            return 0
        if args.command == "access-effective":
            assignments = [
                hydrate_assignment(row) for row in repo.list_payloads("access_assignments")
            ]
            filtered_assignments = [
                item
                for item in assignments
                if item.identity_identifier == args.identity
                and (not args.provider or item.identity_provider == args.provider)
            ]
            evaluation = calculate_effective_accesses(
                filtered_assignments,
                [hydrate_access_relation(row) for row in repo.list_payloads("access_relations")],
                [hydrate_access(row) for row in repo.list_payloads("accesses")],
            )
            for item in evaluation.effective_accesses:
                kind = "direct" if item.direct else "derived"
                print(
                    f"{item.identity_provider}/{item.identity_identifier} "
                    f"{kind} {item.access_provider}/{item.access_name}"
                )
                for path in item.paths:
                    print("  via " + " -> ".join(ref.key() for ref in path.access_chain))
            for diagnostic in evaluation.diagnostics:
                print({"diagnostic": diagnostic})
            return 0
        if args.command == "campaign-export":
            campaigns = repo.list_payloads("campaigns")
            if not campaigns:
                raise SystemExit("No campaign found")
            from access_review_engine.storage import (
                hydrate_campaign,
                hydrate_decision,
                hydrate_golden_version,
                hydrate_review_item,
            )

            campaign = hydrate_campaign(campaigns[-1])
            golden = next(
                (
                    hydrate_golden_version(row)
                    for row in repo.list_payloads("golden_source_versions")
                    if row["id"] == campaign.golden_source_version_id
                ),
                None,
            )
            write_reports(
                args.output_dir,
                campaign,
                [hydrate_review_item(row) for row in repo.list_payloads("review_items") if row["campaign_id"] == campaign.id],
                [hydrate_decision(row) for row in repo.list_payloads("decisions")],
                golden,
            )
            print(f"exported {args.output_dir}")
            return 0
    finally:
        repo.close()
    return 1


def _validate(path: Path) -> None:
    if path.suffix == ".zip":
        source_type = _zip_source_type(path)
        if source_type == "active_directory":
            import_ad_zip(path)
        elif source_type == "openldap":
            import_openldap_zip(path)
        else:
            raise ValueError(f"Unsupported ZIP source_type: {source_type or 'missing'}")
    elif path.suffix.lower() in {".ldif", ".ldap"}:
        import_openldap_ldif(path)
    else:
        raise ValueError("Unsupported validation file type")


if __name__ == "__main__":
    raise SystemExit(main())
