from __future__ import annotations

from pathlib import Path

import pytest

from access_review_engine.collector_runner import build_command
from access_review_engine.config_loader import ConfigError, template, validate_connector


def test_openldap_anonymous_collection_requires_explicit_opt_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = template("crashtests-openldap", "openldap")
    config["connection"]["uri"] = "ldap://crashtests-openldap:389"
    config["connection"]["base_dn"] = "dc=example,dc=com"
    validate_connector(config)
    monkeypatch.delenv("ALLOW_ANONYMOUS", raising=False)
    _, environment = build_command(config, tmp_path / "source.zip", tmp_path)
    assert config["collection"]["allow_anonymous"] is False
    assert "ALLOW_ANONYMOUS" not in environment

    config["collection"]["allow_anonymous"] = True
    validate_connector(config)
    _, opted_in_environment = build_command(config, tmp_path / "source.zip", tmp_path)
    assert opted_in_environment["ALLOW_ANONYMOUS"] == "1"


def test_openldap_anonymous_option_must_be_boolean() -> None:
    config = template("crashtests-openldap", "openldap")
    config["connection"]["uri"] = "ldap://crashtests-openldap:389"
    config["connection"]["base_dn"] = "dc=example,dc=com"
    config["collection"]["allow_anonymous"] = "true"

    with pytest.raises(ConfigError, match="collection.allow_anonymous must be a boolean"):
        validate_connector(config)
