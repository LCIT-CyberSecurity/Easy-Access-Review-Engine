from __future__ import annotations

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from access_review_engine.domain import Identity, IdentityStatus, IdentityType
from access_review_engine.importers.ad import import_ad_zip
from access_review_engine.services import create_snapshot
from ad_test_helpers import zip_fixture


def test_foreign_security_principal_is_not_dropped_when_unresolved(tmp_path: Path) -> None:
    result = import_ad_zip(zip_fixture(tmp_path, "standard"))
    fsp = [a for a in result.assignments if a.origin.raw.get("unresolved_foreign_principal")]
    assert len(fsp) == 1
    assert fsp[0].identity_identifier == "S-1-5-21-900-800-700-1501"
    assert fsp[0].origin.raw["unresolved"] is True
    snapshot = create_snapshot([result.provider], result.identities, [], result.accesses, result.assignments, [result.batch.id])
    row = [item for item in snapshot.comparison_states if item["identity_identifier"] == fsp[0].identity_identifier][0]
    assert "unresolved_foreign_principal" in row["findings"]
    assert "unknown_identity" in row["findings"]


def test_cross_domain_membership_resolves_by_unique_sid(tmp_path: Path) -> None:
    europe_identity = Identity(
        provider="europe-ad",
        identifier="marie.europe",
        native_id="S-1-5-21-900-800-700-1501",
        type=IdentityType.USER_ACCOUNT,
        status=IdentityStatus.ACTIVE,
    )
    result = import_ad_zip(zip_fixture(tmp_path, "standard"), known_identities=[europe_identity])
    assignment = [a for a in result.assignments if a.access_name == "GG_FOREIGN:member"][0]
    assert assignment.identity_provider == "europe-ad"
    assert assignment.identity_identifier == "marie.europe"
    assert assignment.origin.raw["cross_domain_resolved"] is True


def test_unknown_member_type_is_preserved_as_unresolved(tmp_path: Path) -> None:
    archive = tmp_path / "unknown-member.zip"
    with ZipFile(archive, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.yaml", "provider: corp-ad\ncompleteness: full\n")
        zf.writestr("users.csv", "SamAccountName,Enabled,SID\n")
        zf.writestr("groups.csv", "SamAccountName,Name,SID\nGG,GG,S-1-5-21-1-2-3-2200\n")
        zf.writestr(
            "memberships.csv",
            "Group,GroupSID,Member,MemberSID,MemberType,MemberDN,MembershipType\nGG,S-1-5-21-1-2-3-2200,mystery,S-1-5-21-9-9-9-1,customClass,CN=mystery,direct\n",
        )
    result = import_ad_zip(archive)
    assert result.assignments[0].identity_identifier == "S-1-5-21-9-9-9-1"
    assert result.assignments[0].origin.raw["unknown_member_type"] is True
    snapshot = create_snapshot([result.provider], result.identities, [], result.accesses, result.assignments, [result.batch.id])
    assert "unknown_member_type" in snapshot.comparison_states[0]["findings"]


def test_collection_errors_force_unknown_completeness(tmp_path: Path) -> None:
    result = import_ad_zip(zip_fixture(tmp_path, "partial"))
    assert result.batch.completeness == "unknown"
    assert result.batch.scope["collection_errors"] == 1
