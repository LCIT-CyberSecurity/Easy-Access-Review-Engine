from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from access_review_engine.cli.config_loader import ConfigError, load_connector, secret_environment, template, validate_connector
from access_review_engine.cli.main import main
from access_review_engine.cli.runner import build_command


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
