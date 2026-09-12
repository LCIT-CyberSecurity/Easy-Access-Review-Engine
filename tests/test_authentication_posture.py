from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from access_review_engine.authentication import compare_authentication_posture
from access_review_engine.domain import AuthenticationPosture, AuthenticationStatus
from access_review_engine.importers.ad import import_ad_zip
from access_review_engine.importers.openldap import import_openldap_ldif
from access_review_engine.services import create_snapshot
from access_review_engine.storage import hydrate_snapshot


def _ad_zip(path: Path, posture: dict | None = None) -> Path:
    with ZipFile(path, "w", ZIP_DEFLATED) as archive:
        archive.writestr("manifest.yaml", "source_type: active_directory\nprovider: corp-ad\ncompleteness: full\n")
        archive.writestr("users.csv", "SamAccountName,Enabled,SID\n")
        archive.writestr("groups.csv", "SamAccountName,Name,SID\n")
        archive.writestr("memberships.csv", "Group,GroupSID,Member,MemberSID,MemberType\n")
        if posture is not None:
            archive.writestr("authentication-posture.json", json.dumps(posture))
    return path


def test_authentication_comparison_respects_direction_and_unknown() -> None:
    expected = AuthenticationPosture("ldap", {"password_policy": {"expected": 14, "operator": "gte"}, "mfa": {"expected": "required"}})
    observed = AuthenticationPosture("ldap", {"password_policy": {"status": "collected", "value": 12}, "mfa": {"status": "not_supported"}})
    rows = compare_authentication_posture(expected, observed)
    assert rows[0]["assessment"] == "deviation"
    assert rows[1]["assessment"] == "unknown"


def test_ad_authentication_posture_is_optional_and_secret_free(tmp_path: Path) -> None:
    result = import_ad_zip(_ad_zip(tmp_path / "ad.zip", {"provider": "corp-ad", "controls": {"mfa": {"status": "not_supported"}}}))
    assert result.authentication_posture is not None
    assert result.authentication_posture.controls["mfa"]["status"] == AuthenticationStatus.NOT_SUPPORTED
    with pytest.raises(ValueError):
        import_ad_zip(_ad_zip(tmp_path / "secret.zip", {"provider": "corp-ad", "controls": {"token": "secret"}}))


def test_openldap_ppolicy_is_collected_without_user_password(tmp_path: Path) -> None:
    path = tmp_path / "directory.ldif"
    path.write_text("dn: cn=default,ou=Policies,dc=example,dc=com\nobjectClass: pwdPolicy\npwdMinLength: 14\npwdInHistory: 12\npwdMaxAge: 90\nuserPassword: hidden\n\n", encoding="utf-8")
    result = import_openldap_ldif(path, "corp-ldap")
    assert result.authentication_posture is not None
    assert result.authentication_posture.controls["password_policy"]["policies"][0]["controls"]["minimum_length"] == 14
    assert "hidden" not in json.dumps(result.authentication_posture.__dict__)


def test_snapshot_authentication_is_immutable_and_legacy_safe() -> None:
    posture = AuthenticationPosture("ldap", {"password_policy": {"status": "collected", "minimum_length": 14}})
    snapshot = create_snapshot([], [], [], [], [], ["import-1"], authentication_posture=posture)
    restored = hydrate_snapshot({**asdict(snapshot), "providers": [], "identities": [], "resources": [], "accesses": [], "access_assignments": [], "access_relations": [], "comparison_states": []})
    assert restored.authentication_posture is not None
    assert restored.authentication_posture.controls["password_policy"]["minimum_length"] == 14
    legacy = {**snapshot.__dict__, "providers": [], "identities": [], "resources": [], "accesses": [], "access_assignments": [], "access_relations": [], "comparison_states": [], "authentication_posture": None}
    assert hydrate_snapshot(legacy).authentication_posture is None
