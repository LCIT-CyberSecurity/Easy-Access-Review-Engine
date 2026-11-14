from __future__ import annotations

import base64
import uuid
from subprocess import CompletedProcess
from unittest.mock import patch

from aurora.collector_runner import build_command, run_exporter
from aurora.collectors.active_directory_ldap import (
    LDAPCollectionError,
    LDAPSession,
    _all_group_members,
    _filetime,
    _guid,
    _ldap_uri,
    _normalize,
    _parse_ldif,
    _range_bounds,
    _sid,
)
from aurora.config_loader import ConfigError, template, validate_connector


def test_ad_ldap_connector_accepts_plain_ldap_and_requires_base_dn() -> None:
    config = {
        "provider": "corp-ad",
        "type": "active_directory",
        "connection": {"server": "dc.example.test", "protocol": "ldap", "base_dn": "DC=example,DC=test", "tls_mode": "none"},
    }
    validate_connector(config)
    config["connection"].pop("base_dn")
    try:
        validate_connector(config)
    except ConfigError as exc:
        assert "base_dn" in str(exc)
    else:
        raise AssertionError("LDAP mode must require a base DN")


def test_new_active_directory_connector_defaults_to_direct_ldaps() -> None:
    config = template("new-ad", "active_directory")
    assert config["connection"]["protocol"] == "ldap"
    assert config["connection"]["tls_mode"] == "ldaps"
    assert config["collection"]["read_only_account"] is False


def test_ad_ldap_runner_uses_plain_ldap_and_check_only() -> None:
    config = {
        "provider": "corp-ad",
        "type": "active_directory",
        "connection": {"server": "dc.example.test", "protocol": "ldap", "base_dn": "DC=example,DC=test", "tls_mode": "none"},
        "_check_only": True,
    }
    command, env = build_command(config, "/tmp/ad-check.zip")
    assert command[-1] == "aurora.collectors.active_directory_ldap"
    assert env["AURORA_AD_LDAP_TLS_MODE"] == "none"
    assert env["AURORA_AD_LDAP_CHECK_ONLY"] == "1"


def test_ad_ldap_test_credentials_are_runtime_only() -> None:
    config = {
        "provider": "corp-ad", "type": "active_directory",
        "connection": {"server": "dc.example.test", "protocol": "ldap", "base_dn": "DC=example,DC=test", "tls_mode": "none"},
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
        "connection": {"server": "dc.example.test", "protocol": "ldap", "base_dn": "DC=example,DC=test", "tls_mode": "none"},
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


def test_ad_ldap_transport_urls_require_explicit_matching_scheme() -> None:
    assert _ldap_uri("dc.example.org:636", "ldaps") == "ldaps://dc.example.org:636"
    assert _ldap_uri("ldap://dc.example.org:389", "none") == "ldap://dc.example.org:389"
    assert _ldap_uri("ldap://dc.example.org:389", "starttls") == "ldap://dc.example.org:389"
    for server, mode in (("ldaps://dc.example.org", "none"), ("ldap://user:pass@dc", "none"), ("ldap://dc/path", "none")):
        try:
            _ldap_uri(server, mode)
        except ValueError:
            pass
        else:
            raise AssertionError("LDAP URL with an unsafe or mismatched form was accepted")


def test_ad_ldap_session_uses_critical_paging_starttls_and_secret_file() -> None:
    session = LDAPSession(
        "ldap://dc.example.org:389", "DC=example,DC=org", "starttls", 15,
        "bind-user", "/run/secrets/ldap-password", {"LDAPTLS_REQCERT": "demand"}, "secret-value",
    )
    with patch(
        "aurora.collectors.active_directory_ldap.subprocess.run",
        return_value=CompletedProcess([], 0, "dn: DC=example,DC=org\n\n", ""),
    ) as run:
        assert session.search("DC=example,DC=org", "sub", "(objectClass=*)", ["dn"], paged=True)
    command = run.call_args.args[0]
    assert "-ZZ" in command
    assert "!pr=1000/noprompt" in command
    assert command[command.index("-y") + 1] == "/run/secrets/ldap-password"
    assert "secret-value" not in command
    assert session.paged_searches == 1


def test_ad_ldap_session_redacts_bind_secrets_on_authentication_error() -> None:
    session = LDAPSession(
        "ldap://dc.example.org", "DC=example,DC=org", "none", 5,
        "bind-user", "/tmp/password", {}, "secret-value",
    )
    with patch(
        "aurora.collectors.active_directory_ldap.subprocess.run",
        return_value=CompletedProcess([], 49, "", "invalid bind-user secret-value"),
    ):
        try:
            session.search("DC=example,DC=org", "base", "(objectClass=*)", ["dn"])
        except LDAPCollectionError as exc:
            assert "bind-user" not in str(exc)
            assert "secret-value" not in str(exc)
        else:
            raise AssertionError("Failed LDAP authentication should stop collection")


def test_ad_member_range_reads_all_values_and_rejects_gaps() -> None:
    class RangeSession:
        def search(self, _base, _scope, _filter, attributes, **_kwargs):
            start = int(attributes[0].split("=")[1].split("-")[0])
            if start == 1500:
                end = 2999
                attribute = f"member;range={start}-{end}"
            else:
                end = 3499
                attribute = f"member;range={start}-*"
            return [{"dn": ["CN=Big,DC=example,DC=org"], attribute: [f"CN=user-{i}" for i in range(start, end + 1)]}]

    first = {"dn": ["CN=Big,DC=example,DC=org"], "member;range=0-1499": [f"CN=user-{i}" for i in range(1500)]}
    members = _all_group_members(first, RangeSession())
    assert len(members) == 3500
    assert members[0] == "CN=user-0"
    assert members[-1] == "CN=user-3499"
    assert _range_bounds("member;range=1500-*") == (1500, None)
    try:
        _all_group_members({"dn": ["CN=Big"], "member;range=1-2": ["a", "b"]}, RangeSession())
    except LDAPCollectionError as exc:
        assert "start at zero" in str(exc)
    else:
        raise AssertionError("A skipped initial member range was accepted")


def test_ad_filetime_special_values_and_normalized_group_primary_memberships() -> None:
    assert _filetime("0") == ""
    assert _filetime("9223372036854775807") == ""
    sid_prefix = bytes([1, 4]) + (5).to_bytes(6, "big") + b"".join(x.to_bytes(4, "little") for x in (21, 100, 200, 300))
    encoded_user_sid = base64.b64encode(sid_prefix + (1101).to_bytes(4, "little")).decode()
    encoded_group_sid = base64.b64encode(sid_prefix + (513).to_bytes(4, "little")).decode()

    class NoRanges:
        def search(self, *_args, **_kwargs):
            return []

    entries = [
        {"dn": ["DC=example,DC=org"], "objectclass": ["top", "domainDNS"], "objectsid": [base64.b64encode(sid_prefix).decode()]},
        {"dn": ["CN=Domain Users,DC=example,DC=org"], "objectclass": ["top", "group"], "samaccountname": ["Domain Users"], "objectsid": [encoded_group_sid], "grouptype": ["2147483650"], "member": []},
        {"dn": ["CN=alice,DC=example,DC=org"], "objectclass": ["top", "person", "organizationalPerson", "user"], "samaccountname": ["alice"], "objectsid": [encoded_user_sid], "useraccountcontrol": ["512"], "primarygroupid": ["513"]},
    ]
    users, groups, _computers, _services, memberships, domain_sid, base_is_domain = _normalize(entries, NoRanges(), [], "DC=example,DC=org", [])
    assert len(users) == len(groups) == 1
    assert domain_sid == "S-1-5-21-100-200-300" and base_is_domain is True
    assert memberships[0]["MembershipType"] == "primary_group"
    assert memberships[0]["MemberType"] == "user"
