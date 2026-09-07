from __future__ import annotations

import csv
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from access_review_engine.application import import_file_to_repository, persist_import_result
from access_review_engine.domain import (
    Finding,
    GoldenSourceAssignment,
    IdentityStatus,
)
from access_review_engine.importers.ad import import_ad_zip
from access_review_engine.services import create_golden_source, create_golden_version, promote_snapshot
from access_review_engine.storage import Repository
from ad_test_helpers import zip_fixture


def test_same_ad_zip_twice_is_idempotent_in_persistent_cli_path(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    archive = zip_fixture(tmp_path, "standard")
    try:
        first = import_file_to_repository(repo, archive)
        first_provider_id = repo.find_by_name("providers", "corp-ad")["id"]
        first_identity_ids = _ids_by_native(repo, "identities")
        first_access_ids = _ids_by_access_native(repo)
        first_assignment_ids = _ids_by_assignment_key(repo)

        second = import_file_to_repository(repo, archive)

        assert repo.find_by_name("providers", "corp-ad")["id"] == first_provider_id
        assert _ids_by_native(repo, "identities") == first_identity_ids
        assert _ids_by_access_native(repo) == first_access_ids
        assert _ids_by_assignment_key(repo) == first_assignment_ids
        assert len(repo.list_payloads("providers")) == 1
        assert len(repo.list_payloads("identities")) == len(first.identities)
        assert len(repo.list_payloads("accesses")) == len(first.accesses)
        assert len(repo.list_payloads("access_assignments")) == len(first.access_assignments)
        assert len(second.access_assignments) == len(first.access_assignments)
    finally:
        repo.close()


def test_ad_rename_same_sid_keeps_persistent_identity_id(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        import_file_to_repository(repo, _ad_zip(tmp_path, "corp-ad", [("user.old", _sid(1101))], ["GG"], [("GG", _sid(2101), "user.old", _sid(1101), "user")]))
        first = [row for row in repo.list_payloads("identities") if row.get("native_id") == _sid(1101)][0]

        import_file_to_repository(repo, _ad_zip(tmp_path, "corp-ad", [("user.new", _sid(1101))], ["GG"], [("GG", _sid(2101), "user.new", _sid(1101), "user")]))
        identities = [row for row in repo.list_payloads("identities") if row.get("native_id") == _sid(1101)]

        assert len(identities) == 1
        assert identities[0]["id"] == first["id"]
        assert identities[0]["identifier"] == "user.new"
    finally:
        repo.close()


def test_unknown_collection_preserves_authoritative_assignments_and_snapshot_is_unknown(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        full = import_file_to_repository(repo, _many_assignment_zip(tmp_path, "corp-ad", 100, "full"))
        golden = create_golden_version(
            create_golden_source("baseline"),
            [GoldenSourceAssignment(*assignment.comparison_key()) for assignment in full.access_assignments],
            "test",
        )
        unknown_result = import_ad_zip(_many_assignment_zip(tmp_path, "corp-ad", 80, "unknown"), known_identities=[])
        snapshot = persist_import_result(repo, unknown_result, golden_version=golden)

        persisted = repo.list_payloads_by_provider("access_assignments", "corp-ad")
        assert len(persisted) == 100
        classifications = {row["classification"] for row in snapshot.comparison_states}
        findings = {finding for row in snapshot.comparison_states for finding in row["findings"]}
        assert "missing" not in classifications
        assert "unknown_due_to_scope" in classifications
        assert Finding.COLLECTION_INCOMPLETE in findings
    finally:
        repo.close()


def test_full_zero_assignment_import_replaces_only_that_provider(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        import_file_to_repository(repo, _many_assignment_zip(tmp_path, "provider-a", 10, "full"))
        import_file_to_repository(repo, _many_assignment_zip(tmp_path, "provider-b", 5, "full"))
        import_file_to_repository(repo, _many_assignment_zip(tmp_path, "provider-a", 0, "full"))

        assert len(repo.list_payloads_by_provider("access_assignments", "provider-a")) == 0
        assert len(repo.list_payloads_by_provider("access_assignments", "provider-b")) == 5
    finally:
        repo.close()


def test_importing_one_provider_never_replaces_another_provider_assignments(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        import_file_to_repository(repo, _many_assignment_zip(tmp_path, "provider-a", 10, "full"))
        import_file_to_repository(repo, _many_assignment_zip(tmp_path, "provider-b", 20, "full"))
        import_file_to_repository(repo, _many_assignment_zip(tmp_path, "provider-b", 15, "full"))

        assert len(repo.list_payloads_by_provider("access_assignments", "provider-a")) == 10
        assert len(repo.list_payloads_by_provider("access_assignments", "provider-b")) == 15
    finally:
        repo.close()


def test_foreign_principal_unresolved_then_resolved_after_foreign_provider_import(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    foreign_sid = "S-1-5-21-900-800-700-1501"
    try:
        import_file_to_repository(repo, _foreign_member_zip(tmp_path, "provider-a", foreign_sid))
        assignments = repo.list_payloads_by_provider("access_assignments", "provider-a")
        assert assignments[0]["identity_provider"] == ""
        assert assignments[0]["identity_identifier"] == foreign_sid
        assert assignments[0]["origin"]["raw"]["unresolved_foreign_principal"] is True
        assert [row["name"] for row in repo.list_payloads("providers")] == ["provider-a"]
        assert not any(row["provider"] == "provider-a" and row["native_id"] == foreign_sid for row in repo.list_payloads("identities"))

        import_file_to_repository(repo, _ad_zip(tmp_path, "provider-b", [("foreign.user", foreign_sid)], [], []))
        resolved = repo.list_payloads_by_provider("access_assignments", "provider-a")[0]
        assert resolved["identity_provider"] == "provider-b"
        assert resolved["identity_identifier"] == "foreign.user"
        assert "unresolved_foreign_principal" not in resolved["origin"]["raw"]
        assert sum(1 for row in repo.list_payloads("identities") if row["native_id"] == foreign_sid) == 1
    finally:
        repo.close()


def test_foreign_principal_resolves_immediately_when_sid_known_globally(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    foreign_sid = "S-1-5-21-900-800-700-1501"
    try:
        import_file_to_repository(repo, _ad_zip(tmp_path, "provider-b", [("foreign.user", foreign_sid)], [], []))
        import_file_to_repository(repo, _foreign_member_zip(tmp_path, "provider-a", foreign_sid))

        assignment = repo.list_payloads_by_provider("access_assignments", "provider-a")[0]
        assert assignment["identity_provider"] == "provider-b"
        assert assignment["identity_identifier"] == "foreign.user"
        assert assignment["origin"]["raw"]["cross_domain_resolved"] is True
    finally:
        repo.close()


def test_provider_full_import_is_authoritative_only_for_that_provider(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        first_a = import_file_to_repository(
            repo,
            _ad_zip(
                tmp_path,
                "provider-a",
                [("a1", _sid(1101)), ("a2", _sid(1102))],
                ["A1", "A2"],
                [("A1", _sid(2101), "a1", _sid(1101), "user"), ("A2", _sid(2102), "a2", _sid(1102), "user")],
            ),
        )
        first_b = import_file_to_repository(
            repo,
            _ad_zip(
                tmp_path,
                "provider-b",
                [("b1", _sid(1201)), ("b2", _sid(1202))],
                ["B1", "B2"],
                [("B1", _sid(2201), "b1", _sid(1201), "user"), ("B2", _sid(2202), "b2", _sid(1202), "user")],
            ),
        )
        golden = create_golden_version(
            create_golden_source("baseline"),
            [
                GoldenSourceAssignment(*assignment.comparison_key())
                for assignment in [*first_a.access_assignments, *first_b.access_assignments]
            ],
            "test",
        )

        snapshot = import_file_to_repository(
            repo,
            _ad_zip(
                tmp_path,
                "provider-b",
                [("b1", _sid(1201))],
                ["B1", "B2"],
                [("B1", _sid(2201), "b1", _sid(1201), "user")],
                suffix="-b1-only",
            ),
            golden_version=golden,
        )

        states = {
            (row["access_provider"], row["access_name"], row["identity_identifier"]): row["classification"]
            for row in snapshot.comparison_states
        }
        assert states[("provider-b", "B1:member", "b1")] == "expected_and_observed"
        assert states[("provider-b", "B2:member", "b2")] == "missing"
        assert states[("provider-a", "A1:member", "a1")] != "missing"
        assert states[("provider-a", "A2:member", "a2")] != "missing"
    finally:
        repo.close()


def test_deleted_identity_requires_full_authoritative_import(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        import_file_to_repository(repo, _ad_zip(tmp_path, "corp-ad", [("gone", _sid(1101))], [], []))
        import_file_to_repository(repo, _ad_zip(tmp_path, "corp-ad", [], [], [], completeness="unknown"))
        assert repo.list_payloads("identities")[0]["status"] == IdentityStatus.ACTIVE

        import_file_to_repository(
            repo,
            _ad_zip(
                tmp_path,
                "corp-ad",
                [],
                [],
                [],
                completeness="full",
                scope="scope:\n  type: identity_types\n  completeness: full\n",
                suffix="-scoped",
            ),
        )
        assert repo.list_payloads("identities")[0]["status"] == IdentityStatus.ACTIVE

        import_file_to_repository(repo, _ad_zip(tmp_path, "corp-ad", [], [], [], completeness="full", suffix="-full"))
        assert repo.list_payloads("identities")[0]["status"] == IdentityStatus.DELETED
    finally:
        repo.close()


def test_incoherent_completeness_uses_least_authoritative_value(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        full = import_file_to_repository(repo, _many_assignment_zip(tmp_path, "corp-ad", 2, "full"))
        golden = create_golden_version(
            create_golden_source("baseline"),
            [GoldenSourceAssignment(*assignment.comparison_key()) for assignment in full.access_assignments],
            "test",
        )

        snapshot = import_file_to_repository(
            repo,
            _ad_zip(
                tmp_path,
                "corp-ad",
                [("user000", _sid(1100))],
                ["GG"],
                [("GG", _sid(2101), "user000", _sid(1100), "user")],
                completeness="unknown",
                scope="scope:\n  type: all\n  completeness: full\n",
                suffix="-conflict",
            ),
            golden_version=golden,
        )

        assert "unknown" in {row["completeness"] for row in repo.list_payloads("imports")}
        classifications = {row["classification"] for row in snapshot.comparison_states}
        findings = {finding for row in snapshot.comparison_states for finding in row["findings"]}
        assert "missing" not in classifications
        assert "unknown_due_to_scope" in classifications
        assert Finding.COLLECTION_INCOMPLETE in findings
    finally:
        repo.close()


def test_access_sid_controls_reconciliation_not_reused_name(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        import_file_to_repository(
            repo,
            _ad_zip(tmp_path, "corp-ad", [("user", _sid(1101))], [("Finance", _sid(1200))], [("Finance", _sid(1200), "user", _sid(1101), "user")]),
        )
        original = _ids_by_access_native(repo)[_sid(1200)]

        import_file_to_repository(
            repo,
            _ad_zip(
                tmp_path,
                "corp-ad",
                [("user", _sid(1101))],
                [("Finance-Renamed", _sid(1200))],
                [("Finance-Renamed", _sid(1200), "user", _sid(1101), "user")],
                suffix="-renamed",
            ),
        )
        assert _ids_by_access_native(repo)[_sid(1200)] == original
    finally:
        repo.close()


def test_access_same_name_with_new_sid_gets_new_id(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        import_file_to_repository(
            repo,
            _ad_zip(tmp_path, "corp-ad", [("user", _sid(1101))], [("Finance", _sid(1200))], [("Finance", _sid(1200), "user", _sid(1101), "user")]),
        )
        original = _ids_by_access_native(repo)[_sid(1200)]

        import_file_to_repository(
            repo,
            _ad_zip(
                tmp_path,
                "corp-ad",
                [("user", _sid(1101))],
                [("Finance", _sid(1800))],
                [("Finance", _sid(1800), "user", _sid(1101), "user")],
                suffix="-recreated",
            ),
        )
        access_ids = _ids_by_access_native(repo)
        assert access_ids[_sid(1800)] != original
    finally:
        repo.close()


def test_reused_samaccountname_after_tombstone_keeps_both_identities(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        import_file_to_repository(repo, _ad_zip(tmp_path, "corp-ad", [("jdupont", _sid(1101))], [], []))
        old_id = _ids_by_native(repo, "identities")[_sid(1101)]
        import_file_to_repository(repo, _ad_zip(tmp_path, "corp-ad", [], [], [], suffix="-deleted"))
        import_file_to_repository(repo, _ad_zip(tmp_path, "corp-ad", [("jdupont", _sid(1102))], [], [], suffix="-reused"))

        identities = {row["native_id"]: row for row in repo.list_payloads_by_provider("identities", "corp-ad")}
        assert identities[_sid(1101)]["id"] == old_id
        assert identities[_sid(1101)]["status"] == IdentityStatus.DELETED
        assert identities[_sid(1102)]["identifier"] == "jdupont"
        assert identities[_sid(1102)]["status"] == IdentityStatus.ACTIVE
        assert identities[_sid(1102)]["id"] != old_id
    finally:
        repo.close()



def test_ad_golden_identity_rename_same_sid_is_expected_and_observed(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        first = import_file_to_repository(
            repo,
            _ad_zip(tmp_path, "corp-ad", [("user.old", _sid(1101))], [("Finance", _sid(2101))], [("Finance", _sid(2101), "user.old", _sid(1101), "user")], suffix="old"),
        )
        golden = promote_snapshot(create_golden_source("baseline"), first)
        snapshot = import_file_to_repository(
            repo,
            _ad_zip(tmp_path, "corp-ad", [("user.new", _sid(1101))], [("Finance", _sid(2101))], [("Finance", _sid(2101), "user.new", _sid(1101), "user")], suffix="new"),
            golden_version=golden,
        )
        assert {row["classification"] for row in snapshot.comparison_states} == {"expected_and_observed"}
    finally:
        repo.close()


def test_ad_golden_group_rename_same_sid_is_expected_and_observed(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        first = import_file_to_repository(
            repo,
            _ad_zip(tmp_path, "corp-ad", [("user", _sid(1101))], [("Finance", _sid(2101))], [("Finance", _sid(2101), "user", _sid(1101), "user")], suffix="old"),
        )
        golden = promote_snapshot(create_golden_source("baseline"), first)
        snapshot = import_file_to_repository(
            repo,
            _ad_zip(tmp_path, "corp-ad", [("user", _sid(1101))], [("Finance-Renamed", _sid(2101))], [("Finance-Renamed", _sid(2101), "user", _sid(1101), "user")], suffix="new"),
            golden_version=golden,
        )
        assert {row["classification"] for row in snapshot.comparison_states} == {"expected_and_observed"}
    finally:
        repo.close()


def test_ad_golden_same_group_name_new_sid_is_not_expected_and_observed(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        first = import_file_to_repository(
            repo,
            _ad_zip(tmp_path, "corp-ad", [("user", _sid(1101))], [("Finance", _sid(2101))], [("Finance", _sid(2101), "user", _sid(1101), "user")], suffix="old"),
        )
        golden = promote_snapshot(create_golden_source("baseline"), first)
        snapshot = import_file_to_repository(
            repo,
            _ad_zip(tmp_path, "corp-ad", [("user", _sid(1101))], [("Finance", _sid(2201))], [("Finance", _sid(2201), "user", _sid(1101), "user")], suffix="new"),
            golden_version=golden,
        )
        assert "expected_and_observed" not in {row["classification"] for row in snapshot.comparison_states}
        assert {row["classification"] for row in snapshot.comparison_states} == {"missing", "unexpected"}
    finally:
        repo.close()

def _ids_by_native(repo: Repository, table: str) -> dict[str, str]:
    return {row["native_id"]: row["id"] for row in repo.list_payloads(table) if row.get("native_id")}


def _ids_by_access_native(repo: Repository) -> dict[str, str]:
    return {row["control_object"]["native_id"]: row["id"] for row in repo.list_payloads("accesses")}


def _ids_by_assignment_key(repo: Repository) -> dict[tuple[str, str, str, str, str], str]:
    rows = repo.list_payloads("access_assignments")
    return {
        (
            row["provider"],
            row["access_name"],
            row["identity_provider"],
            row["identity_identifier"],
            row["origin"]["raw"].get("membership_type", ""),
        ): row["id"]
        for row in rows
    }


def _many_assignment_zip(tmp_path: Path, provider: str, count: int, completeness: str) -> Path:
    users = [(f"user{i:03d}", _sid(1100 + i)) for i in range(count)]
    memberships = [("GG", _sid(2101), user, sid, "user") for user, sid in users]
    return _ad_zip(tmp_path, provider, users, ["GG"], memberships, completeness=completeness, suffix=f"-{count}-{completeness}")


def _foreign_member_zip(tmp_path: Path, provider: str, foreign_sid: str) -> Path:
    return _ad_zip(
        tmp_path,
        provider,
        [],
        ["GG_FINANCE"],
        [("GG_FINANCE", _sid(2101), foreign_sid, foreign_sid, "foreignSecurityPrincipal")],
        suffix="-foreign",
    )


def _ad_zip(
    tmp_path: Path,
    provider: str,
    users: list[tuple[str, str]],
    groups: list[str | tuple[str, str]],
    memberships: list[tuple[str, str, str, str, str]],
    completeness: str = "full",
    suffix: str = "",
    scope: str = "",
) -> Path:
    archive = tmp_path / f"{provider}{suffix}.zip"
    with ZipFile(archive, "w", ZIP_DEFLATED) as zf:
        zf.writestr(
            "manifest.yaml",
            f"schema_version: 1\nsource_type: active_directory\nprovider: {provider}\ncompleteness: {completeness}\n{scope}statistics:\n  collection_errors: 0\n",
        )
        zf.writestr("users.csv", _csv(["SamAccountName", "Enabled", "SID", "DistinguishedName"], [
            {"SamAccountName": name, "Enabled": "True", "SID": sid, "DistinguishedName": f"CN={name},DC=example,DC=test"}
            for name, sid in users
        ]))
        zf.writestr("groups.csv", _csv(["SamAccountName", "Name", "SID", "GroupScope", "GroupCategory"], [
            {
                "SamAccountName": _group_name(group),
                "Name": _group_name(group),
                "SID": _group_sid(group, index),
                "GroupScope": "Global",
                "GroupCategory": "Security",
            }
            for index, group in enumerate(groups)
        ]))
        zf.writestr("memberships.csv", _csv(["Group", "GroupSID", "Member", "MemberSID", "MemberType", "MemberDN", "MembershipType"], [
            {"Group": group, "GroupSID": group_sid, "Member": member, "MemberSID": member_sid, "MemberType": member_type, "MemberDN": f"CN={member}", "MembershipType": "direct"}
            for group, group_sid, member, member_sid, member_type in memberships
        ]))
        zf.writestr("collection-errors.csv", "ObjectType,ObjectIdentifier,ObjectSID,Operation,ErrorCode,ErrorMessage\n")
    return archive


def _csv(fieldnames: list[str], rows: list[dict[str, str]]) -> str:
    from io import StringIO

    handle = StringIO()
    writer = csv.DictWriter(handle, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return handle.getvalue()


def _group_name(group: str | tuple[str, str]) -> str:
    return group[0] if isinstance(group, tuple) else group


def _group_sid(group: str | tuple[str, str], index: int) -> str:
    return group[1] if isinstance(group, tuple) else _sid(2101 + index)


def _sid(rid: int) -> str:
    return f"S-1-5-21-100-200-300-{rid}"
