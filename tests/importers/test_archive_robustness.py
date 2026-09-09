from __future__ import annotations

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from access_review_engine.application import import_file_to_repository
from access_review_engine.storage import Repository


def test_rejected_ad_archives_do_not_write_partial_repository_state(tmp_path: Path) -> None:
    cases = [
        _ad_archive_with_duplicate_manifest(tmp_path),
        _ad_archive_with_unexpected_file(tmp_path),
        _ad_archive_with_too_many_files(tmp_path),
    ]
    for index, archive in enumerate(cases):
        repo = Repository(tmp_path / f"case-{index}.db")
        try:
            with pytest.raises(ValueError):
                import_file_to_repository(repo, archive)
            assert repo.list_payloads("imports") == []
            assert repo.list_payloads("providers") == []
            assert repo.list_payloads("identities") == []
            assert repo.list_payloads("access_assignments") == []
            assert repo.list_payloads("snapshots") == []
        finally:
            repo.close()


def test_rejected_openldap_archives_do_not_write_partial_repository_state(tmp_path: Path) -> None:
    archive = tmp_path / "bad-openldap.zip"
    with ZipFile(archive, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.yaml", "schema_version: 1\nsource_type: openldap\nprovider: ldap\ncompleteness: full\n")
        zf.writestr("directory.ldif", "")
        zf.writestr("extra.ldif", "")
    repo = Repository(tmp_path / "openldap.db")
    try:
        with pytest.raises(ValueError):
            import_file_to_repository(repo, archive)
        assert repo.list_payloads("imports") == []
        assert repo.list_payloads("snapshots") == []
    finally:
        repo.close()


def _valid_ad_archive(tmp_path: Path, name: str) -> Path:
    archive = tmp_path / name
    with ZipFile(archive, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.yaml", "schema_version: 1\nsource_type: active_directory\nprovider: corp-ad\ncompleteness: full\n")
        zf.writestr("users.csv", "SamAccountName,Enabled,SID\n")
        zf.writestr("groups.csv", "SamAccountName,Name,SID\n")
        zf.writestr("memberships.csv", "Group,GroupSID,Member,MemberSID,MemberType\n")
    return archive


def _ad_archive_with_duplicate_manifest(tmp_path: Path) -> Path:
    archive = _valid_ad_archive(tmp_path, "duplicate-manifest.zip")
    with ZipFile(archive, "a", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.yaml", "schema_version: 1\nsource_type: active_directory\nprovider: duplicate\n")
    return archive


def _ad_archive_with_unexpected_file(tmp_path: Path) -> Path:
    archive = _valid_ad_archive(tmp_path, "unexpected-file.zip")
    with ZipFile(archive, "a", ZIP_DEFLATED) as zf:
        zf.writestr("secret.txt", "must not be accepted")
    return archive


def _ad_archive_with_too_many_files(tmp_path: Path) -> Path:
    archive = tmp_path / "too-many.zip"
    with ZipFile(archive, "w", ZIP_DEFLATED) as zf:
        for index in range(17):
            zf.writestr(f"file-{index}.csv", "x")
    return archive
