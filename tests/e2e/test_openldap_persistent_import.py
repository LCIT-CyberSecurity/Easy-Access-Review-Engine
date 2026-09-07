from __future__ import annotations

import csv
import os
import subprocess
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from access_review_engine.application import import_file_to_repository
from access_review_engine.domain import Finding, GoldenSourceAssignment, IdentityStatus
from access_review_engine.services import create_golden_source, create_golden_version
from access_review_engine.storage import Repository


def test_openldap_zip_routes_through_application_import(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        snapshot = import_file_to_repository(repo, _openldap_zip(tmp_path, _ldif([_user("alice", "uuid-u1"), _group("admins", "uuid-g1", ["uid=alice,ou=People,dc=example,dc=com"])])))
        assert snapshot.providers[0].name == "openldap-prod"
        assert repo.list_payloads("imports")[0]["source_type"] == "openldap_zip"
        assert len(repo.list_payloads("access_assignments")) == 1
    finally:
        repo.close()


def test_zip_router_keeps_ad_and_rejects_unknown_source(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        ad = tmp_path / "ad.zip"
        with ZipFile(ad, "w", ZIP_DEFLATED) as zf:
            zf.writestr("manifest.yaml", "source_type: active_directory\nprovider: corp-ad\ncompleteness: full\n")
            zf.writestr("users.csv", "SamAccountName,Enabled,SID\n")
            zf.writestr("groups.csv", "SamAccountName,Name,SID\n")
            zf.writestr("memberships.csv", "Group,GroupSID,Member,MemberSID,MemberType\n")
        assert import_file_to_repository(repo, ad).providers[0].type == "active_directory"

        unknown = tmp_path / "unknown.zip"
        with ZipFile(unknown, "w", ZIP_DEFLATED) as zf:
            zf.writestr("manifest.yaml", "source_type: unknown\nprovider: x\n")
            zf.writestr("directory.ldif", "")
        with pytest.raises(ValueError):
            import_file_to_repository(repo, unknown)
    finally:
        repo.close()


def test_openldap_same_export_twice_is_idempotent(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    archive = _openldap_zip(tmp_path, _ldif([_user("alice", "uuid-u1"), _group("admins", "uuid-g1", ["uid=alice,ou=People,dc=example,dc=com"])]))
    try:
        import_file_to_repository(repo, archive)
        identity_ids = _ids_by_native(repo, "identities")
        access_ids = _ids_by_access_native(repo)
        assignment_ids = _ids_by_assignment_key(repo)
        import_file_to_repository(repo, archive)
        assert _ids_by_native(repo, "identities") == identity_ids
        assert _ids_by_access_native(repo) == access_ids
        assert _ids_by_assignment_key(repo) == assignment_ids
        assert len(repo.list_payloads("access_assignments")) == 1
    finally:
        repo.close()


def test_openldap_identity_rename_by_entryuuid_keeps_identity_id(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        import_file_to_repository(repo, _openldap_zip(tmp_path, _ldif([_user("jdupont", "uuid-u1", ou="Old")]), suffix="old"))
        old_id = _ids_by_native(repo, "identities")["uuid-u1"]
        import_file_to_repository(repo, _openldap_zip(tmp_path, _ldif([_user("jean.dupont", "uuid-u1", ou="New")]), suffix="new"))
        identity = _by_native(repo, "identities", "uuid-u1")
        assert identity["id"] == old_id
        assert identity["metadata"]["uid"] == "jean.dupont"
        assert identity["metadata"]["dn"] == "uid=jean.dupont,ou=New,dc=example,dc=com"
    finally:
        repo.close()


def test_openldap_group_rename_by_entryuuid_keeps_access_id(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        import_file_to_repository(repo, _openldap_zip(tmp_path, _ldif([_group("Finance", "uuid-g1", [])]), suffix="old"))
        old_id = _ids_by_access_native(repo)["uuid-g1"]
        import_file_to_repository(repo, _openldap_zip(tmp_path, _ldif([_group("Finance-Users", "uuid-g1", [])]), suffix="new"))
        access = _by_access_native(repo, "uuid-g1")
        assert access["id"] == old_id
        assert access["display_name"] == "Finance-Users:member"
    finally:
        repo.close()


def test_openldap_same_cn_in_two_ous_stays_distinct(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    ldif = _ldif([
        _user("alice", "uuid-u1"),
        _group("admins", "uuid-g-linux", ["uid=alice,ou=People,dc=example,dc=com"], ou="Linux"),
        _group("admins", "uuid-g-apps", ["uid=alice,ou=People,dc=example,dc=com"], ou="Applications"),
    ])
    try:
        import_file_to_repository(repo, _openldap_zip(tmp_path, ldif))
        groups = [row for row in repo.list_payloads("identities") if row["type"] == "group"]
        accesses = repo.list_payloads("accesses")
        assignments = repo.list_payloads("access_assignments")
        assert len(groups) == 2
        assert len(accesses) == 2
        assert len(assignments) == 2
        assert {row["native_id"] for row in groups} == {"uuid-g-linux", "uuid-g-apps"}
    finally:
        repo.close()


def test_openldap_recreated_group_same_cn_new_entryuuid_gets_new_access(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        import_file_to_repository(repo, _openldap_zip(tmp_path, _ldif([_group("Finance", "uuid-g1", [])]), suffix="g1"))
        first = _ids_by_access_native(repo)["uuid-g1"]
        import_file_to_repository(repo, _openldap_zip(tmp_path, _ldif([_group("Finance", "uuid-g2", [])]), suffix="g2"))
        assert _ids_by_access_native(repo)["uuid-g2"] != first
    finally:
        repo.close()


def test_openldap_member_dn_resolves_to_uid_not_first_rdn(tmp_path: Path) -> None:
    result = import_file_to_repository(
        Repository(tmp_path / "review.db"),
        _openldap_zip(tmp_path, _ldif([_person_with_cn_dn("Jean Dupont", "jdupont", "uuid-u1"), _group("reviewers", "uuid-g1", ["cn=Jean Dupont,ou=People,dc=example,dc=com"])])),
    )
    row = result.comparison_states[0]
    assert row["identity_identifier"] == "entry:uuid-u1"
    assert Finding.UNKNOWN_IDENTITY not in row["findings"]


def test_openldap_escaped_and_multivalued_dn_resolve(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        ldif = """
dn: cn=Doe\\, John+uid=jdoe,ou=People,dc=example,dc=com
objectClass: inetOrgPerson
entryUUID: uuid-u1
uid: jdoe
cn: Doe, John

dn: cn=reviewers,ou=Groups,dc=example,dc=com
objectClass: groupOfNames
entryUUID: uuid-g1
cn: reviewers
member: cn=Doe\\, John+uid=jdoe,ou=People,dc=example,dc=com
""".strip()
        snapshot = import_file_to_repository(repo, _openldap_zip(tmp_path, ldif))
        assert snapshot.comparison_states[0]["identity_identifier"] == "entry:uuid-u1"
        assert Finding.UNKNOWN_IDENTITY not in snapshot.comparison_states[0]["findings"]
    finally:
        repo.close()


def test_openldap_posix_account_memberuid_resolves(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        ldif = """
dn: uid=alice,ou=People,dc=example,dc=com
objectClass: account
objectClass: posixAccount
entryUUID: uuid-u1
uid: alice
cn: Alice

dn: cn=linux-admins,ou=Groups,dc=example,dc=com
objectClass: posixGroup
entryUUID: uuid-g1
cn: linux-admins
memberUid: alice
""".strip()
        snapshot = import_file_to_repository(repo, _openldap_zip(tmp_path, ldif))
        assert snapshot.comparison_states[0]["identity_identifier"] == "entry:uuid-u1"
        assert Finding.UNKNOWN_IDENTITY not in snapshot.comparison_states[0]["findings"]
    finally:
        repo.close()


def test_raw_ldif_is_unknown_and_does_not_replace_authoritative_state(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        full = import_file_to_repository(repo, _openldap_zip(tmp_path, _bulk_ldif(200, 200), suffix="full"))
        golden = create_golden_version(
            create_golden_source("baseline"),
            [GoldenSourceAssignment(*assignment.comparison_key()) for assignment in full.access_assignments],
            "test",
        )
        raw = tmp_path / "partial.ldif"
        raw.write_text(_bulk_ldif(40, 50), encoding="utf-8")
        snapshot = import_file_to_repository(repo, raw, provider_name="openldap-prod", golden_version=golden)
        assert len(repo.list_payloads_by_provider("identities", "openldap-prod")) >= 201
        assert len(repo.list_payloads_by_provider("access_assignments", "openldap-prod")) == 200
        assert "missing" not in {row["classification"] for row in snapshot.comparison_states}
        assert Finding.COLLECTION_INCOMPLETE in {finding for row in snapshot.comparison_states for finding in row["findings"]}
    finally:
        repo.close()


def test_openldap_full_zero_assignments_replaces_only_current_provider(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        import_file_to_repository(repo, _openldap_zip(tmp_path, _bulk_ldif(10, 10, provider="ldap-a"), provider="ldap-a", suffix="a"))
        import_file_to_repository(repo, _openldap_zip(tmp_path, _bulk_ldif(5, 5, provider="ldap-b"), provider="ldap-b", suffix="b"))
        import_file_to_repository(repo, _openldap_zip(tmp_path, _bulk_ldif(1, 0, provider="ldap-a"), provider="ldap-a", suffix="a0"))
        assert len(repo.list_payloads_by_provider("access_assignments", "ldap-a")) == 0
        assert len(repo.list_payloads_by_provider("access_assignments", "ldap-b")) == 5
    finally:
        repo.close()


def test_openldap_multi_provider_golden_missing_only_current_provider(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        snap_a = import_file_to_repository(repo, _openldap_zip(tmp_path, _bulk_ldif(10, 10, provider="ldap-a"), provider="ldap-a", suffix="a"))
        snap_b = import_file_to_repository(repo, _openldap_zip(tmp_path, _bulk_ldif(20, 20, provider="ldap-b"), provider="ldap-b", suffix="b"))
        golden = create_golden_version(
            create_golden_source("baseline"),
            [GoldenSourceAssignment(*assignment.comparison_key()) for assignment in [*snap_a.access_assignments, *snap_b.access_assignments]],
            "test",
        )
        snapshot = import_file_to_repository(repo, _openldap_zip(tmp_path, _bulk_ldif(15, 15, provider="ldap-b"), provider="ldap-b", suffix="b15"), golden_version=golden)
        assert len(repo.list_payloads_by_provider("access_assignments", "ldap-a")) == 10
        assert len(repo.list_payloads_by_provider("access_assignments", "ldap-b")) == 15
        missing_providers = {row["access_provider"] for row in snapshot.comparison_states if row["classification"] == "missing"}
        assert missing_providers == {"ldap-b"}
    finally:
        repo.close()


def test_openldap_golden_survives_identity_and_group_rename(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        first = import_file_to_repository(repo, _openldap_zip(tmp_path, _ldif([_user("jdupont", "uuid-u1", ou="Paris"), _group("Finance", "uuid-g1", ["uid=jdupont,ou=Paris,dc=example,dc=com"])]), suffix="first"))
        golden = create_golden_version(create_golden_source("baseline"), [GoldenSourceAssignment(*a.comparison_key()) for a in first.access_assignments], "test")
        snapshot = import_file_to_repository(repo, _openldap_zip(tmp_path, _ldif([_user("jean.dupont", "uuid-u1", ou="France"), _group("Finance-Users", "uuid-g1", ["uid=jean.dupont,ou=France,dc=example,dc=com"])]), suffix="renamed"), golden_version=golden)
        assert {row["classification"] for row in snapshot.comparison_states} == {"expected_and_observed"}
    finally:
        repo.close()


def test_openldap_change_records_are_rejected(tmp_path: Path) -> None:
    ldif = tmp_path / "change.ldif"
    ldif.write_text("dn: uid=alice,dc=example,dc=com\nchangetype: modify\nreplace: cn\ncn: Alice\n", encoding="utf-8")
    repo = Repository(tmp_path / "review.db")
    try:
        with pytest.raises(ValueError):
            import_file_to_repository(repo, ldif)
        ldif.write_text("dn: uid=alice,dc=example,dc=com\nchangetype: delete\n", encoding="utf-8")
        with pytest.raises(ValueError):
            import_file_to_repository(repo, ldif)
    finally:
        repo.close()


def test_openldap_known_unknown_status_is_not_unknown_identity(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        snapshot = import_file_to_repository(repo, _openldap_zip(tmp_path, _ldif([_user("alice", "uuid-u1"), _group("admins", "uuid-g1", ["uid=alice,ou=People,dc=example,dc=com"])])))
        findings = snapshot.comparison_states[0]["findings"]
        assert Finding.UNKNOWN_IDENTITY not in findings
        assert Finding.DISABLED_WITH_ACCESS not in findings
    finally:
        repo.close()


def test_openldap_unknown_zero_assignments_surfaces_collection_incomplete_in_cli(tmp_path: Path) -> None:
    db = tmp_path / "review.db"
    archive = _openldap_zip(
        tmp_path,
        _ldif([]),
        manifest_extra="completeness: unknown\nscope:\n  type: all\n  completeness: unknown\n",
        suffix="unknown-empty-cli",
    )
    env = os.environ | {"PYTHONPATH": "src"}
    subprocess.run(
        [sys.executable, "-m", "access_review_engine.cli", "--db", str(db), "import", str(archive)],
        cwd=Path.cwd(),
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    findings = subprocess.run(
        [sys.executable, "-m", "access_review_engine.cli", "--db", str(db), "findings-list"],
        cwd=Path.cwd(),
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "collection_incomplete" in findings.stdout


def test_openldap_unknown_zero_assignments_surfaces_collection_incomplete(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        snapshot = import_file_to_repository(repo, _openldap_zip(tmp_path, _ldif([]), manifest_extra="completeness: unknown\nscope:\n  type: all\n  completeness: unknown\n", suffix="unknown-empty"))
        assert snapshot.comparison_states == []
        assert repo.list_payloads("imports")[0]["completeness"] == "unknown"
        assert repo.list_payloads("imports")[0]["scope"]["completeness"] == "unknown"
    finally:
        repo.close()


def test_openldap_manifest_inconsistencies_force_unknown(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        snapshot = import_file_to_repository(repo, _openldap_zip(tmp_path, _bulk_ldif(1, 0), manifest_extra="completeness: full\nstatistics:\n  collection_errors: 1\n", suffix="errors"))
        assert snapshot.source_import_ids
        assert repo.list_payloads("imports")[0]["completeness"] == "unknown"
    finally:
        repo.close()


def test_openldap_exporter_command_modes_and_manifest(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    log = tmp_path / "ldapsearch.args"
    fake = fake_bin / "ldapsearch"
    fake.write_text(
        "#!/usr/bin/env bash\nprintf '%s\\n' \"$@\" > \"$LDAPSEARCH_LOG\"\nprintf 'dn: uid=alice,ou=People,dc=example,dc=com\\nobjectClass: inetOrgPerson\\nentryUUID: uuid-u1\\nuid: alice\\ncn: Alice\\n'\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    env = os.environ | {"PATH": f"{fake_bin}:{os.environ['PATH']}", "LDAPSEARCH_LOG": str(log), "BASE_DN": "dc=example,dc=com", "ALLOW_ANONYMOUS": "1", "PROVIDER_NAME": "openldap-prod"}
    out = tmp_path / "export.zip"
    subprocess.run(["bash", "exporters/openldap/export-openldap.sh", str(out)], cwd=Path.cwd(), env=env, check=True)
    args = log.read_text(encoding="utf-8")
    assert "entryUUID" in args
    assert "userPassword" not in args
    assert "jpegPhoto" not in args
    assert "-D" not in args

    env = env | {"BIND_DN": "cn=admin,dc=example,dc=com", "LDAP_URI": "ldaps://ldap.example.test", "ALLOW_ANONYMOUS": "0"}
    subprocess.run(["bash", "exporters/openldap/export-openldap.sh", str(tmp_path / "ldaps.zip")], cwd=Path.cwd(), env=env, check=True)
    args = log.read_text(encoding="utf-8")
    assert "-x" in args
    assert "-D" in args
    assert "cn=admin,dc=example,dc=com" in args

    env = env | {"LDAP_URI": "ldap://ldap.example.test", "START_TLS": "1"}
    subprocess.run(["bash", "exporters/openldap/export-openldap.sh", str(tmp_path / "starttls.zip")], cwd=Path.cwd(), env=env, check=True)
    assert "-ZZ" in log.read_text(encoding="utf-8")


def test_openldap_exporter_fails_closed_and_partial_zip_has_unknown_manifest(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake = fake_bin / "ldapsearch"
    fake.write_text("#!/usr/bin/env bash\necho 'Size limit exceeded' >&2\nexit 4\n", encoding="utf-8")
    fake.chmod(0o755)
    env = os.environ | {"PATH": f"{fake_bin}:{os.environ['PATH']}", "BASE_DN": "dc=example,dc=com", "ALLOW_ANONYMOUS": "1"}
    failed = subprocess.run(
        ["bash", "exporters/openldap/export-openldap.sh", str(tmp_path / "fail.zip")],
        cwd=Path.cwd(),
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert failed.returncode == 1

    env = env | {"ALLOW_PARTIAL": "1"}
    partial = tmp_path / "partial.zip"
    subprocess.run(["bash", "exporters/openldap/export-openldap.sh", str(partial)], cwd=Path.cwd(), env=env, check=True)
    with ZipFile(partial) as zf:
        manifest = zf.read("manifest.yaml").decode("utf-8")
        errors = zf.read("collection-errors.csv").decode("utf-8")
    assert "completeness: unknown" in manifest
    assert "collection_errors: 1" in manifest
    assert "Size limit exceeded" in errors
    assert "userPassword" not in manifest


def _ids_by_native(repo: Repository, table: str) -> dict[str, str]:
    return {row["native_id"]: row["id"] for row in repo.list_payloads(table) if row.get("native_id")}


def _ids_by_access_native(repo: Repository) -> dict[str, str]:
    return {row["control_object"]["native_id"]: row["id"] for row in repo.list_payloads("accesses")}


def _ids_by_assignment_key(repo: Repository) -> dict[tuple[str, str, str, str, str], str]:
    return {
        (row["provider"], row["access_name"], row["identity_provider"], row["identity_identifier"], row["origin"]["raw"].get("member_dn") or row["origin"]["raw"].get("memberUid", "")): row["id"]
        for row in repo.list_payloads("access_assignments")
    }


def _by_native(repo: Repository, table: str, native_id: str) -> dict[str, object]:
    return [row for row in repo.list_payloads(table) if row.get("native_id") == native_id][0]


def _by_access_native(repo: Repository, native_id: str) -> dict[str, object]:
    return [row for row in repo.list_payloads("accesses") if row["control_object"].get("native_id") == native_id][0]


def _openldap_zip(tmp_path: Path, ldif: str, provider: str = "openldap-prod", suffix: str = "", manifest_extra: str | None = None) -> Path:
    archive = tmp_path / f"{provider}{suffix}.zip"
    manifest = manifest_extra or "completeness: full\nscope:\n  type: all\n  completeness: full\nstatistics:\n  collection_errors: 0\n"
    with ZipFile(archive, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.yaml", f"schema_version: 1\nsource_type: openldap\nprovider: {provider}\nbase_dn: dc=example,dc=com\nsearch_scope: sub\nfilter: (objectClass=*)\nldapsearch_exit_code: 0\nlimited: false\n{manifest}")
        zf.writestr("directory.ldif", ldif)
        zf.writestr("collection-errors.csv", "ObjectType,ObjectIdentifier,ObjectSID,Operation,ErrorCode,ErrorMessage\n")
    return archive


def _ldif(entries: list[str]) -> str:
    return "\n\n".join(entries)


def _user(uid: str, uuid: str, ou: str = "People") -> str:
    return f"""dn: uid={uid},ou={ou},dc=example,dc=com
objectClass: inetOrgPerson
entryUUID: {uuid}
uid: {uid}
cn: {uid}"""


def _person_with_cn_dn(cn: str, uid: str, uuid: str) -> str:
    return f"""dn: cn={cn},ou=People,dc=example,dc=com
objectClass: inetOrgPerson
entryUUID: {uuid}
uid: {uid}
cn: {cn}"""


def _group(cn: str, uuid: str, members: list[str], ou: str = "Groups") -> str:
    member_lines = "\n".join(f"member: {member}" for member in members)
    return f"""dn: cn={cn},ou={ou},dc=example,dc=com
objectClass: groupOfNames
entryUUID: {uuid}
cn: {cn}
{member_lines}""".strip()


def _bulk_ldif(user_count: int, assignment_count: int, provider: str = "openldap-prod") -> str:
    users = [_user(f"user{i:03d}", f"{provider}-uuid-u{i:03d}") for i in range(user_count)]
    members = [f"uid=user{i:03d},ou=People,dc=example,dc=com" for i in range(min(user_count, assignment_count))]
    while len(members) < assignment_count:
        members.append("uid=user000,ou=People,dc=example,dc=com")
    return _ldif([*users, _group("all", f"{provider}-uuid-g", members)])
