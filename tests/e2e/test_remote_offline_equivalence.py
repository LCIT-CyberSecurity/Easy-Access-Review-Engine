from __future__ import annotations

import csv
import os
import subprocess
from io import StringIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from access_review_engine.application import import_file_to_repository
from access_review_engine.importers.openldap import DEFAULT_OPENLDAP_FILTER
from access_review_engine.storage import Repository


def test_remote_offline_equivalence_active_directory(tmp_path: Path) -> None:
    remote_zip = _ad_zip(tmp_path, "remote-ad")
    offline_zip = _ad_zip(tmp_path, "offline-ad")

    remote = _import_and_normalize(tmp_path / "remote.db", remote_zip)
    offline = _import_and_normalize(tmp_path / "offline.db", offline_zip)

    assert remote == offline


def test_remote_offline_equivalence_openldap(tmp_path: Path) -> None:
    ldif = _openldap_equivalence_ldif()
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake = fake_bin / "ldapsearch"
    fake.write_text("#!/usr/bin/env bash\ncat \"$LDAP_FIXTURE\"\n", encoding="utf-8")
    fake.chmod(0o755)

    remote_zip = tmp_path / "remote-openldap.zip"
    env = os.environ | {
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "LDAP_FIXTURE": str(tmp_path / "remote.ldif"),
        "BASE_DN": "dc=example,dc=com",
        "PROVIDER_NAME": "openldap-prod",
        "ALLOW_ANONYMOUS": "1",
        "PAGE_SIZE": "2",
    }
    Path(env["LDAP_FIXTURE"]).write_text(ldif, encoding="utf-8")
    subprocess.run(["bash", "exporters/openldap/export-openldap.sh", str(remote_zip)], cwd=Path.cwd(), env=env, check=True)

    offline_zip = _openldap_zip(tmp_path, "offline-openldap.zip", ldif)

    remote = _import_and_normalize(tmp_path / "remote-ldap.db", remote_zip)
    offline = _import_and_normalize(tmp_path / "offline-ldap.db", offline_zip)

    assert remote == offline


def _import_and_normalize(db: Path, archive: Path) -> dict[str, object]:
    repo = Repository(db)
    try:
        import_file_to_repository(repo, archive)
        return {
            "imports": [
                {
                    "provider": row["provider"],
                    "source_type": row["source_type"],
                    "status": row["status"],
                    "completeness": row["completeness"],
                    "scope": _stable_scope(row["scope"]),
                }
                for row in repo.list_payloads("imports")
            ],
            "identities": sorted(
                (
                    row["provider"],
                    row["identifier"],
                    row.get("native_id"),
                    row["type"],
                    row["status"],
                    row.get("display_name"),
                    _selected_metadata(row.get("metadata", {})),
                )
                for row in repo.list_payloads("identities")
            ),
            "accesses": sorted(
                (
                    row["provider"],
                    row["name"],
                    row["control_object"].get("native_id"),
                    row.get("display_name"),
                    row.get("permission", {}).get("name"),
                )
                for row in repo.list_payloads("accesses")
            ),
            "assignments": sorted(
                (
                    row["provider"],
                    row["access_name"],
                    row["identity_provider"],
                    row["identity_identifier"],
                    row["origin"].get("assignment_type"),
                    _stable_raw(row["origin"].get("raw", {})),
                )
                for row in repo.list_payloads("access_assignments")
            ),
            "snapshots": [
                {"assignments": len(row["access_assignments"])}
                for row in repo.list_payloads("snapshots")
            ],
        }
    finally:
        repo.close()


def _stable_scope(scope: dict[str, object]) -> dict[str, object]:
    ignored = {"generated_at"}
    return {key: value for key, value in sorted(scope.items()) if key not in ignored}


def _selected_metadata(metadata: dict[str, object]) -> tuple[tuple[str, object], ...]:
    keys = {"dn", "uid", "entry_uuid", "object_guid", "primary_group_id", "group_scope", "group_category"}
    return tuple(sorted((key, value) for key, value in metadata.items() if key in keys))


def _stable_raw(raw: dict[str, object]) -> tuple[tuple[str, object], ...]:
    return tuple(sorted(raw.items()))


def _ad_zip(tmp_path: Path, name: str) -> Path:
    archive = tmp_path / f"{name}.zip"
    with ZipFile(archive, "w", ZIP_DEFLATED) as zf:
        zf.writestr(
            "manifest.yaml",
            "schema_version: 1\n"
            "source_type: active_directory\n"
            "provider: corp-ad\n"
            "domain: corp.example.test\n"
            "domain_sid: S-1-5-21-100-200-300\n"
            "completeness: full\n"
            "scope:\n"
            "  type: all\n"
            "  completeness: full\n"
            "statistics:\n"
            "  users: 1\n"
            "  groups: 2\n"
            "  service_accounts: 0\n"
            "  computers: 1\n"
            "  memberships: 3\n"
            "  collection_errors: 0\n",
        )
        zf.writestr("users.csv", _csv(["SamAccountName", "UserPrincipalName", "DisplayName", "Enabled", "SID", "DistinguishedName", "PrimaryGroupID", "ObjectGUID"], [["alice", "alice@corp.example.test", "Alice", "True", "S-1-5-21-100-200-300-1101", "CN=Alice,DC=corp,DC=example,DC=test", "513", "11111111-1111-1111-1111-111111111111"]]))
        zf.writestr("computers.csv", _csv(["SamAccountName", "Name", "SID", "DistinguishedName", "Enabled", "DNSHostName", "Description", "ObjectGUID", "PrimaryGroupID"], [["PC001$", "PC001", "S-1-5-21-100-200-300-4101", "CN=PC001,DC=corp,DC=example,DC=test", "True", "pc001.corp.example.test", "", "22222222-2222-2222-2222-222222222222", "515"]]))
        zf.writestr("service_accounts.csv", _csv(["SamAccountName", "SID", "DistinguishedName", "Enabled", "ObjectClass", "PrimaryGroupID"], []))
        zf.writestr("groups.csv", _csv(["SamAccountName", "Name", "SID", "DistinguishedName", "Description", "GroupScope", "GroupCategory"], [["Domain Users", "Domain Users", "S-1-5-21-100-200-300-513", "CN=Domain Users,CN=Users,DC=corp,DC=example,DC=test", "", "Global", "Security"], ["Domain Computers", "Domain Computers", "S-1-5-21-100-200-300-515", "CN=Domain Computers,CN=Users,DC=corp,DC=example,DC=test", "", "Global", "Security"]]))
        zf.writestr("memberships.csv", _csv(["Group", "GroupSID", "Member", "MemberSID", "MemberType", "MemberDN", "MembershipType"], [["Domain Users", "S-1-5-21-100-200-300-513", "alice", "S-1-5-21-100-200-300-1101", "user", "CN=Alice,DC=corp,DC=example,DC=test", "primary_group"], ["Domain Computers", "S-1-5-21-100-200-300-515", "PC001$", "S-1-5-21-100-200-300-4101", "computer", "CN=PC001,DC=corp,DC=example,DC=test", "primary_group"], ["Domain Users", "S-1-5-21-100-200-300-513", "S-1-5-21-900-800-700-1501", "S-1-5-21-900-800-700-1501", "foreignSecurityPrincipal", "CN=S-1-5-21-900-800-700-1501,CN=ForeignSecurityPrincipals,DC=corp,DC=example,DC=test", "direct"]]))
        zf.writestr("collection-errors.csv", "ObjectType,ObjectIdentifier,ObjectSID,Operation,ErrorCode,ErrorMessage\n")
    return archive


def _csv(headers: list[str], rows: list[list[str]]) -> str:
    stream = StringIO()
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(headers)
    writer.writerows(rows)
    return stream.getvalue()


def _openldap_zip(tmp_path: Path, name: str, ldif: str) -> Path:
    archive = tmp_path / name
    with ZipFile(archive, "w", ZIP_DEFLATED) as zf:
        zf.writestr(
            "manifest.yaml",
            "schema_version: 1\n"
            "source_type: openldap\n"
            "provider: openldap-prod\n"
            "base_dn: dc=example,dc=com\n"
            "search_scope: sub\n"
            f"filter: {DEFAULT_OPENLDAP_FILTER}\n"
            "ldapsearch_exit_code: 0\n"
            "limited: false\n"
            "completeness: full\n"
            "scope:\n"
            "  type: all\n"
            "  base_dn: dc=example,dc=com\n"
            "  search_scope: sub\n"
            f"  filter: {DEFAULT_OPENLDAP_FILTER}\n"
            "  completeness: full\n"
            "statistics:\n"
            "  collection_errors: 0\n",
        )
        zf.writestr("directory.ldif", ldif)
        zf.writestr("collection-errors.csv", "ObjectType,ObjectIdentifier,ObjectSID,Operation,ErrorCode,ErrorMessage\n")
    return archive


def _openldap_equivalence_ldif() -> str:
    return """dn: uid=alice,ou=People,dc=example,dc=com
objectClass: inetOrgPerson
entryUUID: uuid-u1
uid: alice
cn: Alice


dn: uid=bob,ou=People,dc=example,dc=com
objectClass: posixAccount
entryUUID: uuid-u2
uid: bob
cn: Bob


dn: cn=reviewers,ou=Groups,dc=example,dc=com
objectClass: groupOfNames
entryUUID: uuid-g1
cn: reviewers
member: uid=alice,ou=People,dc=example,dc=com


dn: cn=approvers,ou=Groups,dc=example,dc=com
objectClass: groupOfUniqueNames
entryUUID: uuid-g2
cn: approvers
uniqueMember: uid=alice,ou=People,dc=example,dc=com#'0101'B


dn: cn=linux-admins,ou=Groups,dc=example,dc=com
objectClass: posixGroup
entryUUID: uuid-g3
cn: linux-admins
memberUid: bob
""".strip()
