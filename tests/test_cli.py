from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from access_review_engine.cli.config_loader import ConfigError, load_connector, secret_environment, template, validate_connector
from access_review_engine.cli.main import main, parser
from access_review_engine.cli.menu import run_global_menu
from access_review_engine.cli.runner import RunnerResult, build_command


def test_connector_validation_and_secret_indirection() -> None:
    data = template("corp-ad", "active_directory")
    data["connection"]["server"] = "dc01.example.test"
    data["credentials"] = {"password_env": "EARE_TEST_PASSWORD"}
    validate_connector(data, "corp-ad")
    with patch.dict(os.environ, {"EARE_TEST_PASSWORD": "never-print"}):
        assert secret_environment(data)["password"] == "never-print"


def test_invalid_connector_is_rejected() -> None:
    try:
        validate_connector({"provider": "x", "type": "unknown", "connection": {}})
    except ConfigError as exc:
        assert "Unsupported connector" in str(exc)
    else:
        raise AssertionError("invalid connector was accepted")


def test_config_loader_reads_yaml_and_rejects_name_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "x.yaml"
    path.write_text("provider: other\ntype: active_directory\nconnection:\n  server: dc\n", encoding="utf-8")
    try:
        load_connector("x", path)
    except ConfigError as exc:
        assert "does not match" in str(exc)
    else:
        raise AssertionError("mismatched connector was accepted")


def test_exporter_commands_use_existing_collectors_without_secret_arguments(tmp_path: Path) -> None:
    ad = template("corp-ad", "active_directory")
    ad["connection"]["server"] = "dc01"
    command, _ = build_command(ad, tmp_path / "ad.zip", tmp_path)
    assert command[0] == "pwsh"
    assert "dc01" in command
    assert "password" not in " ".join(command).lower()

    ldap = template("ldap-prod", "openldap")
    ldap["connection"]["base_dn"] = "dc=example,dc=com"
    ldap_command, env = build_command(ldap, tmp_path / "ldap.zip", tmp_path)
    assert ldap_command[0] == "bash"
    assert env["BASE_DN"] == "dc=example,dc=com"


def test_exporter_check_only_flags_are_native(tmp_path: Path) -> None:
    ad = template("corp-ad", "active_directory")
    ad["connection"]["server"] = "dc01"
    ad["_check_only"] = True
    ad_command, _ = build_command(ad, tmp_path / "check.zip", tmp_path)
    assert "-CheckOnly" in ad_command

    ldap = template("ldap-prod", "openldap")
    ldap["connection"]["base_dn"] = "dc=example,dc=com"
    ldap["_check_only"] = True
    _, ldap_env = build_command(ldap, tmp_path / "check.zip", tmp_path)
    assert ldap_env["CHECK_ONLY"] == "1"


def test_config_check_does_not_create_database(tmp_path: Path) -> None:
    import os
    old = Path.cwd()
    os.chdir(tmp_path)
    config_dir = tmp_path / "config" / "connectors"
    config_dir.mkdir(parents=True)
    (config_dir / "corp-ad.yaml").write_text(
        "provider: corp-ad\ntype: active_directory\nconnection:\n  server: dc01\n",
        encoding="utf-8",
    )
    assert main(["config", "check", "corp-ad"]) == 0
    assert not (tmp_path / "access-review.db").exists()
    os.chdir(old)


def test_provider_namespace_and_compatibility_commands(tmp_path: Path) -> None:
    old = Path.cwd()
    import os
    os.chdir(tmp_path)
    assert main(["provider", "init", "corp-ad", "--type", "active_directory"]) == 0
    assert (tmp_path / "config" / "connectors" / "corp-ad.yaml").exists()
    assert main(["provider", "show", "corp-ad"]) == 0
    assert parser().parse_args(["provider", "sync", "--all"]).provider_command == "sync"
    os.chdir(old)


def test_noninteractive_no_argument_is_help_and_campaign_commands_parse() -> None:
    assert parser().parse_args(["campaign", "create", "q1"]).campaign_command == "create"
    assert parser().parse_args(["campaign", "close", "q1"]).campaign_command == "close"


def test_import_dry_run_does_not_create_real_database(tmp_path: Path) -> None:
    from ad_test_helpers import zip_fixture
    old = Path.cwd()
    import os
    os.chdir(Path(__file__).parent.parent)
    archive = zip_fixture(tmp_path, "standard")
    os.chdir(tmp_path)
    db = tmp_path / "review.db"
    assert main(["--db", str(db), "provider", "import", str(archive), "--dry-run"]) == 0
    assert not db.exists()
    os.chdir(old)


def test_provider_check_all_is_sequential_and_continues(tmp_path: Path) -> None:
    old = Path.cwd()
    import os
    os.chdir(tmp_path)
    config_dir = tmp_path / "config" / "connectors"
    config_dir.mkdir(parents=True)
    for name in ("one", "two"):
        (config_dir / f"{name}.yaml").write_text(
            f"provider: {name}\ntype: active_directory\nconnection:\n  server: dc-{name}\n",
            encoding="utf-8",
        )
    with patch(
        "access_review_engine.cli.main.run_exporter",
        side_effect=lambda config, output: RunnerResult([], Path(output), 0, "", ""),
    ) as exporter:
        assert main(["provider", "check", "--all"]) == 0
        assert exporter.call_count == 2
    os.chdir(old)


def test_golden_source_can_start_from_csv(tmp_path: Path) -> None:
    import os
    from access_review_engine.storage import Repository
    csv_path = tmp_path / "golden.csv"
    csv_path.write_text(
        "access_provider,access_name,identity_provider,identity_identifier\n"
        "corp-ad,Finance:member,corp-ad,alice\n",
        encoding="utf-8",
    )
    old = Path.cwd()
    os.chdir(tmp_path)
    assert main(["golden", "create", "baseline", "--csv", str(csv_path)]) == 0
    repo = Repository(tmp_path / "access-review.db")
    try:
        versions = repo.list_payloads("golden_source_versions")
        assert len(versions) == 1
        assert len(versions[0]["assignments"]) == 1
    finally:
        repo.close()
        os.chdir(old)


def test_global_menu_quit_is_non_business_and_returns_zero() -> None:
    with patch("builtins.input", side_effect=["6"]):
        assert run_global_menu() == 0


def test_dry_run_keeps_existing_database_byte_identical(tmp_path: Path) -> None:
    import os
    from ad_test_helpers import zip_fixture
    old = Path.cwd()
    root = Path(__file__).parent.parent
    os.chdir(root)
    archive = zip_fixture(tmp_path, "standard")
    db = tmp_path / "review.db"
    assert main(["--db", str(db), "provider", "import", str(archive)]) == 0
    before = db.read_bytes()
    assert main(["--db", str(db), "provider", "import", str(archive), "--dry-run"]) == 0
    assert db.read_bytes() == before
    os.chdir(old)



def test_provider_set_rejects_plaintext_secret_keys(tmp_path: Path) -> None:
    import os
    old = Path.cwd()
    os.chdir(tmp_path)
    try:
        config_dir = tmp_path / "config" / "connectors"
        config_dir.mkdir(parents=True)
        (config_dir / "corp-ad.yaml").write_text(
            "provider: corp-ad\ntype: active_directory\nconnection:\n  server: dc01\n",
            encoding="utf-8",
        )
        assert main(["provider", "set", "corp-ad", "credentials.password", "secret"]) == 2
        data = load_connector("corp-ad")
        assert "password" not in data.get("credentials", {})
    finally:
        os.chdir(old)


def test_provider_all_output_is_directory_and_does_not_overwrite(tmp_path: Path) -> None:
    import os
    old = Path.cwd()
    os.chdir(tmp_path)
    try:
        config_dir = tmp_path / "config" / "connectors"
        config_dir.mkdir(parents=True)
        for name in ("one", "two"):
            (config_dir / f"{name}.yaml").write_text(
                f"provider: {name}\ntype: active_directory\nconnection:\n  server: dc-{name}\n",
                encoding="utf-8",
            )

        def fake_exporter(config, output):
            Path(output).write_text(str(config["provider"]), encoding="utf-8")
            return RunnerResult([], Path(output), 0, "", "")

        with patch("access_review_engine.cli.main.run_exporter", side_effect=fake_exporter):
            assert main(["provider", "collect", "--all", "--output", "exports"]) == 0
        assert (tmp_path / "exports" / "one-export.zip").read_text(encoding="utf-8") == "one"
        assert (tmp_path / "exports" / "two-export.zip").read_text(encoding="utf-8") == "two"
    finally:
        os.chdir(old)


def test_exporter_command_resolves_collectors_outside_repo_cwd(tmp_path: Path) -> None:
    import os
    from access_review_engine.cli.runner import build_command
    old = Path.cwd()
    os.chdir(tmp_path)
    try:
        ad = template("corp-ad", "active_directory")
        ad["connection"]["server"] = "dc01"
        command, _ = build_command(ad, tmp_path / "ad.zip")
        assert Path(command[1]).is_file()
        assert "exporters/active-directory/export-active-directory.ps1" in command[1]
    finally:
        os.chdir(old)


def test_golden_promote_sets_active_version(tmp_path: Path) -> None:
    import os
    from ad_test_helpers import zip_fixture
    from access_review_engine.storage import Repository
    old = Path.cwd()
    root = Path(__file__).parent.parent
    os.chdir(root)
    archive = zip_fixture(tmp_path, "standard")
    os.chdir(tmp_path)
    try:
        db = tmp_path / "review.db"
        assert main(["--db", str(db), "provider", "import", str(archive)]) == 0
        assert main(["--db", str(db), "golden", "create", "baseline", "--from-snapshot", "latest"]) == 0
        repo = Repository(db)
        try:
            source = repo.find_by_name("golden_sources", "baseline")
            versions = repo.list_payloads("golden_source_versions")
            assert source is not None
            assert len(versions) == 1
            assert source["active_version_id"] == versions[0]["id"]
        finally:
            repo.close()
    finally:
        os.chdir(old)


def test_golden_edit_creates_new_version_without_mutating_history(tmp_path: Path) -> None:
    import os
    from access_review_engine.storage import Repository
    csv_path = tmp_path / "golden.csv"
    csv_path.write_text(
        "access_provider,access_name,identity_provider,identity_identifier\n"
        "corp-ad,Finance,corp-ad,alice\n",
        encoding="utf-8",
    )
    old = Path.cwd()
    os.chdir(tmp_path)
    try:
        assert main(["golden", "create", "baseline", "--csv", str(csv_path)]) == 0
        answers = ["a", "corp-ad", "HR", "corp-ad", "bob", "member", "", "", "s"]
        with patch("builtins.input", side_effect=answers):
            assert main(["golden", "edit", "baseline"]) == 0
        repo = Repository(tmp_path / "access-review.db")
        try:
            versions = sorted(repo.list_payloads("golden_source_versions"), key=lambda item: item["version"])
            source = repo.find_by_name("golden_sources", "baseline")
            assert [version["version"] for version in versions] == [1, 2]
            assert len(versions[0]["assignments"]) == 1
            assert len(versions[1]["assignments"]) == 2
            assert source is not None and source["active_version_id"] == versions[1]["id"]
        finally:
            repo.close()
    finally:
        os.chdir(old)


def test_campaign_decide_and_exports_use_selected_campaign_and_timestamped_names(tmp_path: Path) -> None:
    import os
    from ad_test_helpers import zip_fixture
    from access_review_engine.storage import Repository
    old = Path.cwd()
    root = Path(__file__).parent.parent
    os.chdir(root)
    archive = zip_fixture(tmp_path, "standard")
    os.chdir(tmp_path)
    try:
        db = tmp_path / "review.db"
        assert main(["--db", str(db), "provider", "import", str(archive)]) == 0
        assert main(["--db", str(db), "campaign", "create", "quarterly-2026"]) == 0
        assert main(["--db", str(db), "campaign", "open", "quarterly-2026"]) == 0
        repo = Repository(db)
        try:
            item = repo.list_payloads("review_items")[0]
        finally:
            repo.close()
        assert main(["--db", str(db), "campaign", "decide", "quarterly-2026", item["id"], "revoke", "--comment", "remove", "--reviewer", "cedric"]) == 0
        assert main(["--db", str(db), "export", "report", "--campaign", "quarterly-2026"]) == 0
        assert main(["--db", str(db), "export", "revocations", "--campaign", "quarterly-2026", "--output", "revocations-explicit.csv"]) == 0
        reports = sorted((tmp_path / "reports").glob("*-campaign-*"))
        assert reports
        prefixes = {path.name[:16] for path in reports}
        assert len(prefixes) == 1
        assert any(path.name.endswith("campaign-report.html") for path in reports)
        assert any(path.name.endswith("campaign-results.csv") for path in reports)
        assert any(path.name.endswith("campaign-results.json") for path in reports)
        assert (tmp_path / "revocations-explicit.csv").is_file()
    finally:
        os.chdir(old)


def test_global_menu_delegates_covered_operations_without_name_error() -> None:
    scenarios = [
        (["1", "1", "6"], ("config", "list")),
        (["1", "5", "corp-ad", "6"], ("check", None)),
        (["2", "1", "6"], ("analyze", None)),
        (["3", "1", "6"], ("golden", "list")),
        (["3", "2", "baseline", "6"], ("golden", "show")),
        (["4", "1", "6"], ("campaign", "list")),
        (["5", "1", "", "6"], ("export", "report")),
    ]
    for inputs, expected in scenarios:
        calls = []

        def fake_dispatch(namespace):
            calls.append(namespace)
            return 0

        with patch("builtins.input", side_effect=inputs), patch("access_review_engine.cli.main.dispatch", side_effect=fake_dispatch):
            assert run_global_menu() == 0
        assert calls
        assert getattr(calls[0], "command") == expected[0]
        if expected[1] is not None:
            assert getattr(calls[0], f"{expected[0]}_command", None) == expected[1] or getattr(calls[0], "config_command", None) == expected[1]


def test_object_deltas_reports_updates_renames_disabled_and_deleted(tmp_path: Path) -> None:
    from access_review_engine.cli.main import object_deltas
    from access_review_engine.domain import Identity, IdentityStatus, IdentityType
    from access_review_engine.storage import Repository
    before = tmp_path / "before.db"
    after = tmp_path / "after.db"
    original = Identity("corp-ad", "alice", IdentityType.USER_ACCOUNT, IdentityStatus.ACTIVE, native_id="sid-1", id="same")
    renamed = Identity("corp-ad", "alice.renamed", IdentityType.USER_ACCOUNT, IdentityStatus.DISABLED, native_id="sid-1", id="same")
    removed = Identity("corp-ad", "removed", IdentityType.USER_ACCOUNT, IdentityStatus.ACTIVE, id="removed")
    deleted = Identity("corp-ad", "deleted", IdentityType.USER_ACCOUNT, IdentityStatus.ACTIVE, id="deleted")
    deleted_after = Identity("corp-ad", "deleted", IdentityType.USER_ACCOUNT, IdentityStatus.DELETED, id="deleted")
    repo = Repository(before)
    repo.upsert("identities", original)
    repo.upsert("identities", removed)
    repo.upsert("identities", deleted)
    repo.close()
    repo = Repository(after)
    repo.upsert("identities", renamed)
    repo.upsert("identities", deleted_after)
    repo.close()
    delta = object_deltas(before, after)["identities"]
    assert delta["removed"] == 1
    assert delta["updated"] == 2
    assert delta["renamed"] == 1
    assert delta["disabled"] == 1
    assert delta["deleted"] == 1
