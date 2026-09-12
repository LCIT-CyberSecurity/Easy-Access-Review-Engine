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
