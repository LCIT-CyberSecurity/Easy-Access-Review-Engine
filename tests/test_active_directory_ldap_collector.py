from __future__ import annotations

import base64
import uuid
from subprocess import CompletedProcess
from unittest.mock import patch

from aurora.collector_runner import build_command, run_exporter
from aurora.collectors.active_directory_ldap import _parse_ldif, _sid, _guid
from aurora.config_loader import ConfigError, validate_connector


def test_ad_ldap_connector_accepts_plain_ldap_and_requires_base_dn() -> None:
    config = {
        "provider": "corp-ad",
        "type": "active_directory",
        "connection": {"server": "192.168.1.100", "protocol": "ldap", "base_dn": "DC=lcit,DC=local", "tls_mode": "none"},
    }
    validate_connector(config)
    config["connection"].pop("base_dn")
    try:
        validate_connector(config)
    except ConfigError as exc:
        assert "base_dn" in str(exc)
    else:
        raise AssertionError("LDAP mode must require a base DN")


def test_ad_ldap_runner_uses_plain_ldap_and_check_only() -> None:
    config = {
        "provider": "corp-ad",
        "type": "active_directory",
        "connection": {"server": "192.168.1.100", "protocol": "ldap", "base_dn": "DC=lcit,DC=local", "tls_mode": "none"},
        "_check_only": True,
    }
    command, env = build_command(config, "/tmp/ad-check.zip")
    assert command[-1] == "aurora.collectors.active_directory_ldap"
    assert env["AURORA_AD_LDAP_TLS_MODE"] == "none"
    assert env["AURORA_AD_LDAP_CHECK_ONLY"] == "1"


def test_ad_ldap_test_credentials_are_runtime_only() -> None:
    config = {
        "provider": "corp-ad", "type": "active_directory",
        "connection": {"server": "192.168.1.100", "protocol": "ldap", "base_dn": "DC=lcit,DC=local", "tls_mode": "none"},
        "_check_only": True,
    }
    with patch("aurora.collector_runner.subprocess.run", return_value=CompletedProcess([], 0, "ok", "")) as run:
        run_exporter(config, "/tmp/ad-check.zip", secret_overrides={"username": "bind-user", "password": "bind-pass"})
    command = run.call_args.args[0]
    environment = run.call_args.kwargs["env"]
    assert "bind-pass" not in command
    assert environment["AURORA_LDAP_USERNAME"] == "bind-user"
    assert environment["AURORA_LDAP_PASSWORD"] == "bind-pass"


def test_ad_ldap_password_file_reference_is_forwarded_without_reading_secret() -> None:
    config = {
        "provider": "corp-ad", "type": "active_directory",
        "connection": {"server": "192.168.1.100", "protocol": "ldap", "base_dn": "DC=lcit,DC=local", "tls_mode": "none"},
        "credentials": {"username_env": "TEST_LDAP_USER", "password_file_env": "TEST_LDAP_PASSWORD_FILE"},
        "_check_only": True,
    }
    with patch.dict("os.environ", {"TEST_LDAP_USER": "bind-user", "TEST_LDAP_PASSWORD_FILE": "/run/secrets/ldap-password"}):
        with patch("aurora.collector_runner.subprocess.run", return_value=CompletedProcess([], 0, "ok", "")) as run:
            run_exporter(config, "/tmp/ad-check.zip")
    environment = run.call_args.kwargs["env"]
    assert environment["AURORA_LDAP_USERNAME"] == "bind-user"
    assert environment["AURORA_LDAP_PASSWORD_FILE"] == "/run/secrets/ldap-password"
    assert "AURORA_LDAP_PASSWORD" not in environment


def test_ad_ldap_ldif_parser_decodes_sid_guid_and_folded_lines() -> None:
    sid_raw = bytes([1, 2]) + (5).to_bytes(6, "big") + (21).to_bytes(4, "little") + (1001).to_bytes(4, "little")
    guid = uuid.uuid4()
    ldif = "\n".join([
        "dn: CN=paul,DC=lcit,DC=local",
        "sAMAccountName: paul",
        f"objectSid:: {base64.b64encode(sid_raw).decode()}",
        f"objectGUID:: {base64.b64encode(guid.bytes_le).decode()}",
        "description: Paul",
        " Marchand",
        "",
    ])
    entry = _parse_ldif(ldif)[0]
    assert entry["description"] == ["PaulMarchand"]
    assert _sid(entry) == "S-1-5-21-1001"
    assert _guid(entry) == str(guid)
