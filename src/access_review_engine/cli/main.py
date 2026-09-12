from __future__ import annotations
import argparse
import csv
import json
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any
from access_review_engine.application import import_file_to_repository, load_classification_rules, _zip_source_type
from access_review_engine.cli.config_loader import ConfigError, connector_path, load_connector, secret_environment, template, validate_connector
from access_review_engine.cli.runner import RunnerError, run_exporter
from access_review_engine.cli.menu import run_global_menu
from access_review_engine.domain import Campaign, CampaignStatus, Finding, GoldenSourceAssignment
from access_review_engine.importers.ad import import_ad_zip
from access_review_engine.importers.openldap import import_openldap_ldif, import_openldap_zip
from access_review_engine.reporting import write_reports
from access_review_engine.services import calculate_effective_accesses, close_campaign, create_golden_source, create_golden_version, golden_diff, open_campaign, promote_snapshot, remediation_from_decisions
from access_review_engine.storage import (
    Repository, hydrate_access, hydrate_access_relation, hydrate_assignment,
    hydrate_campaign, hydrate_decision, hydrate_golden_source, hydrate_golden_version,
    hydrate_review_item, hydrate_snapshot,
)

CONFIG_CODE, COLLECTION_CODE, IMPORT_CODE = 2, 5, 6

def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="eare", description="Universal IDP-agnostic access review engine")
    p.add_argument("--db", default="access-review.db")
    p.add_argument("--config", dest="config_path")
    p.add_argument("--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)
    provider = sub.add_parser("provider", help="manage providers and run provider operations")
    provider_sub = provider.add_subparsers(dest="provider_command", required=True)
    provider_sub.add_parser("list").set_defaults(command="config", config_command="list")
    for provider_action in ("check", "collect", "sync"):
        action = provider_sub.add_parser(provider_action)
        action.add_argument("provider", nargs="?")
        action.add_argument("--all", action="store_true")
        action.add_argument("--output")
        action.add_argument("--dry-run", action="store_true")
        action.set_defaults(command=provider_action)
    pi = provider_sub.add_parser("init")
    pi.add_argument("provider")
    pi.add_argument("--type", required=True, choices=["active_directory", "openldap"])
    pi.set_defaults(command="config", config_command="init")
    ps = provider_sub.add_parser("set")
    ps.add_argument("provider"); ps.add_argument("key"); ps.add_argument("value")
    ps.set_defaults(command="config", config_command="set")
    for action_name in ("show", "edit"):
        action = provider_sub.add_parser(action_name); action.add_argument("provider")
        action.set_defaults(command="provider_meta", provider_action=action_name)
    setup = provider_sub.add_parser("setup")
    setup.set_defaults(command="provider_setup")
    pci = provider_sub.add_parser("import")
    pci.add_argument("file"); pci.add_argument("--provider", default="openldap"); pci.add_argument("--classification-rules"); pci.add_argument("--dry-run", action="store_true")
    pci.set_defaults(command="import")
    c = sub.add_parser("config"); cs = c.add_subparsers(dest="config_command", required=True)
    cs.add_parser("list")
    s = cs.add_parser("show"); s.add_argument("provider")
    i = cs.add_parser("init"); i.add_argument("provider"); i.add_argument("--type", required=True, choices=["active_directory", "openldap"])
    st = cs.add_parser("set"); st.add_argument("provider"); st.add_argument("key"); st.add_argument("value")
    cc = cs.add_parser("check"); cc.add_argument("provider")
    for name in ("check", "collect", "sync"):
        x = sub.add_parser(name); x.add_argument("provider", nargs="?"); x.add_argument("--all", action="store_true"); x.add_argument("--output"); x.add_argument("--dry-run", action="store_true")
    i = sub.add_parser("import"); i.add_argument("file"); i.add_argument("--provider", default="openldap"); i.add_argument("--classification-rules"); i.add_argument("--dry-run", action="store_true")
    v = sub.add_parser("validate"); v.add_argument("file")
    sub.add_parser("findings-list")
    x = sub.add_parser("identities-list"); x.add_argument("--provider")
    x = sub.add_parser("access-effective"); x.add_argument("identity"); x.add_argument("--provider")
    x = sub.add_parser("analyze"); x.add_argument("--provider"); x.add_argument("--identity"); x.add_argument("--access")
    g = sub.add_parser("golden"); gs = g.add_subparsers(dest="golden_command", required=True)
    gs.add_parser("list"); x = gs.add_parser("show"); x.add_argument("name"); x = gs.add_parser("diff"); x.add_argument("name")
    x = gs.add_parser("promote"); x.add_argument("name"); x.add_argument("--snapshot", default="latest")
    x = gs.add_parser("edit"); x.add_argument("name"); x.add_argument("--csv")
    x = gs.add_parser("create"); x.add_argument("name"); x.add_argument("--csv")
    c = sub.add_parser("campaign"); cs = c.add_subparsers(dest="campaign_command", required=True)
    cs.add_parser("list")
    x = cs.add_parser("create"); x.add_argument("name"); x.add_argument("--snapshot", default="latest")
    x = cs.add_parser("open"); x.add_argument("name")
    x = cs.add_parser("status"); x.add_argument("name", nargs="?")
    x = cs.add_parser("close"); x.add_argument("name")
    x = cs.add_parser("export"); x.add_argument("output_dir")
    e = sub.add_parser("export"); es = e.add_subparsers(dest="export_command", required=True); x = es.add_parser("report"); x.add_argument("--output", required=True); x = es.add_parser("revocations"); x.add_argument("--output", default="revocations.csv")
    return p

def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if not arguments:
        if sys.stdin.isatty() and sys.stdout.isatty():
            return run_global_menu()
        parser().print_help()
        return 0
    try:
        return dispatch(parser().parse_args(arguments))
    except ConfigError as exc:
        print(f"CONFIGURATION_ERROR: {exc}", file=sys.stderr); return CONFIG_CODE
    except RunnerError as exc:
        print(f"COLLECTION_ERROR: {exc}", file=sys.stderr); return COLLECTION_CODE
    except (ValueError, FileNotFoundError) as exc:
        print(f"EARE_ERROR: {exc}", file=sys.stderr); return IMPORT_CODE

def dispatch(a: argparse.Namespace) -> int:
    if a.command == "config": return config_command(a)
    if a.command == "provider_meta": return provider_meta_command(a)
    if a.command == "provider_setup": return provider_setup_command()
    if a.command == "check" and getattr(a, "config_command", None) == "check": return config_check(a)
    if a.command in {"check", "collect", "sync"}: return connector_command(a)
    if a.command in {"import", "validate"}: return import_command(a)
    if a.command in {"findings-list", "identities-list", "access-effective", "analyze"}: return local_command(a)
    if a.command == "golden": return golden_command(a)
    if a.command == "campaign": return campaign_command(a)
    if a.command == "export": return export_command(a)
    return 1

def config_command(a: argparse.Namespace) -> int:
    directory = Path("config/connectors"); directory.mkdir(parents=True, exist_ok=True)
    if a.config_command == "list":
        for path in sorted(directory.glob("*.yaml")): print(path.stem)
        return 0
    path = connector_path(a.provider, directory)
    if a.config_command == "init":
        if path.exists(): raise ConfigError(f"Connector configuration already exists: {path}")
        import yaml
        path.write_text(yaml.safe_dump(template(a.provider, a.type), sort_keys=False), encoding="utf-8")
        print(f"created {path}"); return 0
    data = load_connector(a.provider, getattr(a, "config_path", None))
    if a.config_command == "show":
        print(json.dumps(redact(data), indent=2)); return 0
    if a.config_command == "check":
        validate_connector(data); secret_environment(data); print(f"valid {a.provider}"); return 0
    import yaml
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    cursor = raw
    parts = a.key.split(".")
    for key in parts[:-1]: cursor = cursor.setdefault(key, {})
    cursor[parts[-1]] = parse_value(a.value)
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    print(f"updated {path}"); return 0



def provider_meta_command(a: argparse.Namespace) -> int:
    import yaml
    path = connector_path(a.provider)
    if not path.is_file():
        raise ConfigError(f"Connector configuration not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if a.provider_action == "show":
        print(json.dumps(redact(data), indent=2))
        return 0
    current = data
    print(f"Editing provider {a.provider}. Press Enter to keep the current value.")
    if data["type"] == "active_directory":
        value = input(f"Server [{data['connection'].get('server', '')}]: ").strip()
        if value: current["connection"]["server"] = value
    else:
        for key in ("uri", "base_dn", "bind_dn"):
            value = input(f"{key} [{data['connection'].get(key, '')}]: ").strip()
            if value: current["connection"][key] = value
    collection = current.setdefault("collection", {})
    if data["type"] == "active_directory":
        value = input(f"Timeout [{collection.get('timeout', 300)}]: ").strip()
        if value: collection["timeout"] = parse_value(value)
    else:
        value = input(f"Command timeout [{collection.get('command_timeout', 180)}]: ").strip()
        if value: collection["command_timeout"] = parse_value(value)
    value = input(f"Allow partial [{collection.get('allow_partial', False)}]: ").strip()
    if value: collection["allow_partial"] = parse_value(value)
    connector_path(a.provider).write_text(yaml.safe_dump({k:v for k,v in current.items() if k != "_path"}, sort_keys=False), encoding="utf-8")
    print(f"updated {connector_path(a.provider)}")
    return 0

def provider_setup_command() -> int:
    import yaml
    kind = input("Provider type (active_directory/openldap): ").strip()
    if kind not in {"active_directory", "openldap"}: raise ConfigError("Unsupported provider type")
    name = input("Provider name: ").strip()
    if not name: raise ConfigError("Provider name is required")
    data = template(name, kind)
    connection = data["connection"]
    for key in tuple(connection):
        connection[key] = input(f"{key}: ").strip()
    collection = data["collection"]
    timeout_prompt = "Command timeout" if kind == "openldap" else "Timeout"
    timeout_key = "command_timeout" if kind == "openldap" else "timeout"
    value = input(f"{timeout_prompt} [{collection.get(timeout_key)}]: ").strip()
    if value: collection[timeout_key] = parse_value(value)
    value = input("Allow partial [false]: ").strip()
    if value: collection["allow_partial"] = parse_value(value) if value else False
    data["credentials"] = {
        "username_env": input("Username environment variable (optional): ").strip(),
        "password_env": input("Password environment variable (optional): ").strip(),
        "password_file_env": input("Password file environment variable (optional): ").strip(),
    }
    data["credentials"] = {k:v for k,v in data["credentials"].items() if v}
    path = connector_path(name); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    print(f"created {path}")
    return 0

def read_golden_csv(path: str | Path) -> list[GoldenSourceAssignment]:
    required = {"access_provider", "access_name", "identity_provider", "identity_identifier"}
    assignments: list[GoldenSourceAssignment] = []
    with Path(path).open(newline="", encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            if not required.issubset(row):
                raise ValueError("Golden CSV requires access_provider, access_name, identity_provider, identity_identifier")
            assignments.append(GoldenSourceAssignment(
                access_provider=row["access_provider"],
                access_name=row["access_name"],
                identity_provider=row["identity_provider"],
                identity_identifier=row["identity_identifier"],
                access_native_id=row.get("access_native_id") or None,
                access_permission=row.get("access_permission") or None,
                identity_native_id=row.get("identity_native_id") or None,
            ))
    return assignments

def edit_golden_source(repo: Repository, source: dict[str, Any]) -> int:
    import yaml
    description = input(f"Description [{source.get('description') or ''}]: ").strip()
    if description: source["description"] = description
    repo.upsert("golden_sources", source)
    print(f"updated Golden Source {source['name']}")
    return 0

def config_check(a: argparse.Namespace) -> int:
    data = load_connector(a.provider, a.config_path)
    secret_environment(data); print(f"valid {data['provider']} ({data['type']})"); return 0

def connector_command(a: argparse.Namespace) -> int:
    names = sorted(path.stem for path in Path("config/connectors").glob("*.yaml")) if a.all else [a.provider]
    if not names or names == [None]: raise ConfigError("A provider or --all is required")
    failures = 0
    for name in names:
        try:
            data = load_connector(str(name), a.config_path if len(names) == 1 else None)
            secrets = secret_environment(data)
            if secrets.get("password_file"): data.setdefault("credentials", {})["password_file"] = secrets["password_file"]
            if a.command == "check":
                with tempfile.TemporaryDirectory() as d:
                    result = run_exporter(data, Path(d) / "check.zip")
                if result.returncode: raise RunnerError(result.stderr.strip() or "collector check failed")
                print(f"{name} OK")
                continue
            output = Path(a.output or f"{name}-export.zip")
            if a.command == "sync" and a.dry_run:
                with tempfile.TemporaryDirectory() as d:
                    artifact = Path(d) / output.name
                    run_checked(data, artifact)
                    dry_import(artifact, a, str(name))
            else:
                run_checked(data, output)
                print(f"{name} collected {output}")
                if a.command == "sync": import_real(output, a, str(name))
        except (ConfigError, RunnerError, ValueError) as exc:
            failures += 1; print(f"{name} FAILED {exc}", file=sys.stderr)
    return 1 if failures else 0

def run_checked(data: dict[str, object], output: Path) -> None:
    result = run_exporter(data, output)
    if result.returncode:
        raise RunnerError(result.stderr.strip() or f"collector exited {result.returncode}")
    if not output.is_file():
        raise RunnerError("collector completed without producing an artifact")

def import_command(a: argparse.Namespace) -> int:
    if a.command == "validate":
        path = Path(a.file)
        if path.suffix.lower() == ".zip":
            kind = _zip_source_type(path)
            if kind == "active_directory": import_ad_zip(path)
            elif kind == "openldap": import_openldap_zip(path)
            else: raise ValueError("Unsupported ZIP source type")
        elif path.suffix.lower() in {".ldif", ".ldap"}: import_openldap_ldif(path)
        else: raise ValueError("Unsupported validation file type")
        print("valid"); return 0
    if a.dry_run:
        dry_import(Path(a.file), a, a.provider)
    else:
        with repository(a.db) as repo: snapshot = import_file_to_repository(repo, a.file, provider_name=a.provider, classification_rules=load_classification_rules(a.classification_rules))
        print(f"imported provider={snapshot.providers[0].name if snapshot.providers else a.provider} snapshot={snapshot.id}")
    return 0

def import_real(path: Path, a: argparse.Namespace, provider: str) -> None:
    with repository(a.db) as repo:
        snapshot = import_file_to_repository(repo, path, provider_name=provider)
    print(f"imported provider={provider} snapshot={snapshot.id}")

def dry_import(path: Path, a: argparse.Namespace, provider: str) -> None:
    target = Path(tempfile.mkdtemp()) / "dry-run.db"
    before = table_counts(a.db)
    try:
        backup_if_present(a.db, target)
        with repository(target) as repo:
            snapshot = import_file_to_repository(repo, path, provider_name=provider)
        after = table_counts(target)
        changed = {table: {"before": before[table], "after": after[table]} for table in before if before[table] != after[table]}
        object_changes = object_deltas(a.db, target)
        states: dict[str, int] = {}
        for row in snapshot.comparison_states:
            state = str(row.get("classification", "unknown"))
            states[state] = states.get(state, 0) + 1
        incomplete = any(Finding.COLLECTION_INCOMPLETE in row.get("findings", []) for row in snapshot.comparison_states)
        print(f"EARE DRY RUN {provider}")
        print(f"Changes: {json.dumps(changed, sort_keys=True)}")
        print(f"Objects: {json.dumps(object_changes, sort_keys=True)}")
        print(f"Comparison: {json.dumps(states, sort_keys=True)}")
        print(f"Collection incomplete: {'YES' if incomplete else 'NO'}")
        print("Persistence: NONE (--dry-run)")
    finally:
        shutil.rmtree(target.parent, ignore_errors=True)

def object_deltas(before_path: str | Path, after_path: str | Path) -> dict[str, dict[str, int]]:
    from access_review_engine.storage import TABLES
    def records(path: str | Path, table: str) -> set[str]:
        if not Path(path).exists():
            return set()
        connection = sqlite3.connect(path)
        try:
            return {str(row[0]) for row in connection.execute(f"SELECT id FROM {table}")}
        finally:
            connection.close()
    result: dict[str, dict[str, int]] = {}
    for table in TABLES:
        before = records(before_path, table)
        after = records(after_path, table)
        if before != after:
            result[table] = {"added": len(after - before), "removed": len(before - after)}
    return result

def table_counts(path: str | Path) -> dict[str, int]:
    from access_review_engine.storage import TABLES
    counts = {table: 0 for table in TABLES}
    if not Path(path).exists():
        return counts
    connection = sqlite3.connect(path)
    try:
        for table in counts:
            counts[table] = int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
    finally:
        connection.close()
    return counts

class repository:
    def __init__(self, path: str | Path): self.path = path; self.repo: Repository | None = None
    def __enter__(self) -> Repository: self.repo = Repository(self.path); return self.repo
    def __exit__(self, *_: object) -> None:
        assert self.repo is not None; self.repo.close()

def backup_if_present(source: str | Path, target: Path) -> None:
    if not Path(source).exists(): return
    src = sqlite3.connect(source); dst = sqlite3.connect(target)
    try: src.backup(dst)
    finally: dst.close(); src.close()

def local_command(a: argparse.Namespace) -> int:
    if not Path(a.db).exists():
        if a.command == "analyze":
            print("No snapshot available.\n\nRun:\n  eare sync <provider>\nor:\n  eare import <file>")
        return 0
    with repository(a.db) as repo:
        if a.command == "identities-list":
            for row in repo.list_payloads("identities"):
                if not a.provider or row["provider"] == a.provider: print(f"{row['provider']}/{row['identifier']} {row['type']} {row['status']}")
        elif a.command == "findings-list":
            rows = repo.list_payloads("snapshots")
            for row in (rows[-1].get("comparison_states", []) if rows else []):
                if row.get("findings") or row.get("classification") != "expected_and_observed": print(row)
            imports = repo.list_payloads("imports")
            if imports and imports[-1].get("completeness") != "full":
                print({"finding": "collection_incomplete", "import_id": imports[-1]["id"], "provider": imports[-1]["provider"]})
        elif a.command == "access-effective":
            assignments = [hydrate_assignment(r) for r in repo.list_payloads("access_assignments") if r["identity_identifier"] == a.identity and (not a.provider or r["identity_provider"] == a.provider)]
            evaluation = calculate_effective_accesses(assignments, [hydrate_access_relation(r) for r in repo.list_payloads("access_relations")], [hydrate_access(r) for r in repo.list_payloads("accesses")])
            for item in evaluation.effective_accesses: print(f"{item.identity_provider}/{item.identity_identifier} {'direct' if item.direct else 'derived'} {item.access_provider}/{item.access_name}")
            for diagnostic in evaluation.diagnostics: print(json.dumps(diagnostic, sort_keys=True))
        else:
            snapshots = repo.list_payloads("snapshots")
            if not snapshots:
                print("No snapshot available.\n\nRun:\n  eare sync <provider>\nor:\n  eare import <file>"); return 0
            rows = snapshots[-1].get("comparison_states", [])
            for row in rows:
                if a.provider and row.get("access_provider") != a.provider: continue
                if a.identity and row.get("identity_identifier") != a.identity: continue
                if a.access and row.get("access_name") != a.access: continue
                print(json.dumps(row, sort_keys=True))
    return 0

def golden_command(a: argparse.Namespace) -> int:
    with repository(a.db) as repo:
        sources = repo.list_payloads("golden_sources")
        if a.golden_command == "list":
            for row in sources: print(f"{row['name']} active_version={row.get('active_version_id')}")
            return 0
        source = next((r for r in sources if r["name"] == a.name), None)
        if a.golden_command in {"create", "edit"} and source is None:
            source_object = create_golden_source(a.name)
            repo.upsert("golden_sources", source_object)
            source = repo.find_by_name("golden_sources", a.name)
        if source is None: raise ValueError(f"Golden Source not found: {a.name}")
        if a.golden_command == "show": print(json.dumps(source, indent=2)); return 0
        versions = [hydrate_golden_version(r) for r in repo.list_payloads("golden_source_versions") if r["golden_source_id"] == source["id"]]
        if a.golden_command in {"create", "edit"} and getattr(a, "csv", None):
            assignments = read_golden_csv(a.csv)
            version = create_golden_version(
                hydrate_golden_source(source), assignments,
                "csv", versions, comment="Imported from CSV",
            )
            repo.insert_append_only("golden_source_versions", version)
            source["active_version_id"] = version.id
            repo.upsert("golden_sources", source)
            print(f"created Golden Source version={version.version} assignments={len(assignments)}")
            return 0
        if a.golden_command == "create":
            version = create_golden_version(hydrate_golden_source(source), [], "from_scratch", versions)
            repo.insert_append_only("golden_source_versions", version)
            source["active_version_id"] = version.id
            repo.upsert("golden_sources", source)
            print(f"created Golden Source version={version.version} assignments=0")
            return 0
        if a.golden_command == "edit": return edit_golden_source(repo, source)
        if a.golden_command == "diff":
            if len(versions) < 2: print("No previous Golden Source version available"); return 0
            old, new = sorted(versions, key=lambda x: x.version)[-2:]
            for row in golden_diff(old, new): print(row)
            return 0
        snaps = repo.list_payloads("snapshots")
        selected = snaps[-1] if snaps else None
        if a.snapshot != "latest": selected = next((r for r in snaps if r["id"] == a.snapshot), None)
        if not selected: raise ValueError("Snapshot not found")
        version = promote_snapshot(hydrate_golden_source(source), hydrate_snapshot(selected), versions)
        repo.insert_append_only("golden_source_versions", version)
        print(f"promoted version={version.version}")
    return 0

def campaign_command(a: argparse.Namespace) -> int:
    with repository(a.db) as repo:
        campaigns = repo.list_payloads("campaigns")
        if a.campaign_command == "list":
            for row in campaigns:
                print(f"{row['name']} {row['status']}")
            return 0
        if a.campaign_command == "status":
            selected = campaigns if not a.name else [r for r in campaigns if r["name"] == a.name]
            if not selected:
                raise ValueError("Campaign not found")
            for row in selected:
                print(json.dumps({"name": row["name"], "status": row["status"], "snapshot_id": row["snapshot_id"]}, sort_keys=True))
            return 0
        if a.campaign_command == "create":
            snapshots = repo.list_payloads("snapshots")
            selected = snapshots[-1] if snapshots else None
            if a.snapshot != "latest":
                selected = next((r for r in snapshots if r["id"] == a.snapshot), None)
            if selected is None:
                raise ValueError("Snapshot not found")
            campaign = Campaign(a.name, selected["id"], allow_unresolved_reviewers=True)
            repo.upsert("campaigns", campaign)
            print(f"created campaign={campaign.name} snapshot={campaign.snapshot_id}")
            return 0
        selected = next((r for r in campaigns if r["name"] == a.name), None)
        if selected is None:
            raise ValueError("Campaign not found")
        campaign = hydrate_campaign(selected)
        if a.campaign_command == "open":
            snapshot_payload = repo.get_payload("snapshots", campaign.snapshot_id)
            if snapshot_payload is None:
                raise ValueError("Campaign snapshot not found")
            snapshot = hydrate_snapshot(snapshot_payload)
            campaign, items = open_campaign(campaign, snapshot)
            repo.upsert("campaigns", campaign)
            for item in items:
                repo.upsert("review_items", item)
            print(f"opened campaign={campaign.name} items={len(items)}")
            return 0
        if a.campaign_command == "close":
            items = [hydrate_review_item(r) for r in repo.list_payloads("review_items") if r["campaign_id"] == campaign.id]
            ids = {item.id for item in items}
            decisions = [hydrate_decision(r) for r in repo.list_payloads("decisions") if r["review_item_id"] in ids]
            campaign = close_campaign(campaign, items, decisions)
            repo.upsert("campaigns", campaign)
            print(f"closed campaign={campaign.name}")
            return 0
        items = [hydrate_review_item(r) for r in repo.list_payloads("review_items") if r["campaign_id"] == campaign.id]
        ids = {item.id for item in items}
        decisions = [hydrate_decision(r) for r in repo.list_payloads("decisions") if r["review_item_id"] in ids]
        write_reports(a.output_dir, campaign, items, decisions)
        print(f"exported {a.output_dir}")
    return 0

def export_command(a: argparse.Namespace) -> int:
    if a.export_command == "revocations":
        with repository(a.db) as repo:
            campaigns = repo.list_payloads("campaigns")
            if not campaigns:
                raise ValueError("No campaign found")
            campaign = hydrate_campaign(campaigns[-1])
            items = [hydrate_review_item(r) for r in repo.list_payloads("review_items") if r["campaign_id"] == campaign.id]
            item_ids = {item.id for item in items}
            decisions = [hydrate_decision(r) for r in repo.list_payloads("decisions") if r["review_item_id"] in item_ids]
            actions = remediation_from_decisions(items, decisions)
        output = Path(a.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["action", "review_item_id", "identity_provider", "identity_identifier", "access_provider", "access_name"])
            writer.writeheader()
            by_id = {item.id: item for item in items}
            for action in actions:
                item = by_id[action.review_item_id]
                writer.writerow({"action": action.action, "review_item_id": item.id, "identity_provider": item.identity_provider, "identity_identifier": item.identity_identifier, "access_provider": item.access_provider, "access_name": item.access_name})
        print(f"exported {output} actions={len(actions)}")
        return 0
    return campaign_command(argparse.Namespace(db=a.db, campaign_command="export", output_dir=a.output))

def parse_value(value: str) -> object:
    if value.lower() in {"true", "false"}: return value.lower() == "true"
    try: return int(value)
    except ValueError: return value

def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if any(x in str(k).lower() for x in ("password", "secret", "token", "private")) else redact(v)) for k, v in value.items() if not str(k).startswith("_")}
    if isinstance(value, list): return [redact(v) for v in value]
    return value

if __name__ == "__main__":
    raise SystemExit(main())
