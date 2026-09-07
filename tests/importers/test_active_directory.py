from __future__ import annotations

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from access_review_engine.domain import IdentityStatus, IdentityType
from access_review_engine.importers.ad import import_ad_zip
from ad_test_helpers import zip_fixture


def test_standard_users_groups_memberships_and_metadata(tmp_path: Path) -> None:
    result = import_ad_zip(zip_fixture(tmp_path, "standard"))
    identities = {identity.identifier: identity for identity in result.identities}
    assert result.batch.completeness == "full"
    assert identities["jean.dupont"].native_id == "S-1-5-21-100-200-300-1101"
    assert identities["jean.dupont"].metadata["object_guid"] == "11111111-1111-1111-1111-111111111111"
    assert identities["disabled.user"].status == IdentityStatus.DISABLED
    assert identities["expired.user"].status == IdentityStatus.ACTIVE
    assert identities["expired.user"].metadata["account_expired"] is True
    assert identities["locked.user"].metadata["locked_out"] is True
    assert identities["GG_FINANCE"].metadata["group_scope"] == "Global"
    assert identities["DL_OFFICE"].metadata["group_category"] == "Distribution"


def test_managed_service_accounts_and_computers_are_technical_accounts(tmp_path: Path) -> None:
    result = import_ad_zip(zip_fixture(tmp_path, "standard"))
    identities = {identity.identifier: identity for identity in result.identities}
    assert identities["gmsa_web$"].type == IdentityType.TECHNICAL_ACCOUNT
    assert identities["gmsa_web$"].metadata["principal_kind"] == "managed_service_account"
    assert identities["gmsa_web$"].metadata["managed_service_account_type"] == "gmsa"
    assert identities["msa_batch$"].metadata["managed_service_account_type"] == "msa"
    assert identities["PC001$"].type == IdentityType.TECHNICAL_ACCOUNT
    assert identities["PC001$"].metadata["principal_kind"] == "computer"
    assignments = {(a.access_name, a.identity_identifier) for a in result.assignments}
    assert ("GG_GMSA:member", "gmsa_web$") in assignments
    assert ("GG_COMPUTERS:member", "PC001$") in assignments


def test_builtin_accounts_detected_by_rid_not_name(tmp_path: Path) -> None:
    result = import_ad_zip(zip_fixture(tmp_path, "standard"))
    identities = {identity.identifier: identity for identity in result.identities}
    assert identities["Administrator"].built_in is True
    assert identities["Administrator"].type == IdentityType.USER_ACCOUNT


def test_primary_group_membership_is_represented_without_flattening_nested_groups(tmp_path: Path) -> None:
    result = import_ad_zip(zip_fixture(tmp_path, "standard"))
    assignments = {(a.access_name, a.identity_identifier, a.origin.raw["membership_type"]) for a in result.assignments}
    assert ("Domain Users:member", "jean.dupont", "primary_group") in assignments
    assert ("GG_ALL_FINANCE:member", "GG_FINANCE", "direct") in assignments
    assert ("GG_ALL_FINANCE:member", "jean.dupont", "direct") not in assignments


def test_unicode_and_csv_quoting_are_preserved(tmp_path: Path) -> None:
    result = import_ad_zip(zip_fixture(tmp_path, "standard"))
    identity = {identity.identifier: identity for identity in result.identities}["Dupont.Jerome"]
    assert identity.display_name == "Dupont, Jérôme"
    assert identity.description == "Direction — Finance, Paris"
    assert identity.metadata["distinguished_name"] == "CN=Dupont\\, Jérôme,OU=Users,DC=corp,DC=local"


def test_zip_validation_rejects_duplicates_and_allows_v1_without_optional_files(tmp_path: Path) -> None:
    archive = tmp_path / "duplicate.zip"
    with ZipFile(archive, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.yaml", "provider: corp-ad\n")
        zf.writestr("manifest.yaml", "provider: corp-ad\n")
        zf.writestr("users.csv", "SamAccountName\n")
        zf.writestr("groups.csv", "SamAccountName\n")
        zf.writestr("memberships.csv", "Group\n")
    with pytest.raises(ValueError):
        import_ad_zip(archive)

    old = tmp_path / "old-v1.zip"
    with ZipFile(old, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.yaml", "provider: old-ad\n")
        zf.writestr("users.csv", "SamAccountName,Enabled,SID\nlegacy,true,S-1-5-21-1-2-3-1100\n")
        zf.writestr("groups.csv", "SamAccountName,Name,SID\nGG,GG,S-1-5-21-1-2-3-2200\n")
        zf.writestr("memberships.csv", "Group,GroupSID,Member,MemberSID,MemberType\nGG,S-1-5-21-1-2-3-2200,legacy,S-1-5-21-1-2-3-1100,user\n")
    result = import_ad_zip(old)
    assert result.batch.completeness == "unknown"
    assert result.assignments[0].origin.raw["membership_type"] == "direct"


def test_classic_service_and_shared_accounts_use_deterministic_rules(tmp_path: Path) -> None:
    rules = {
        "technical_account": {
            "samaccountname_prefixes": ["svc_", "svc-"],
            "dn_contains": ["OU=Service Accounts"],
            "has_service_principal_name": True,
        },
        "shared_account": {"samaccountname_prefixes": ["shared_", "generic_"]},
    }
    result = import_ad_zip(zip_fixture(tmp_path, "standard"), classification_rules=rules)
    identities = {identity.identifier: identity for identity in result.identities}
    assert identities["svc_sql"].type == IdentityType.TECHNICAL_ACCOUNT

    old = tmp_path / "shared.zip"
    with ZipFile(old, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.yaml", "provider: old-ad\ncompleteness: full\n")
        zf.writestr("users.csv", "SamAccountName,Enabled,SID\nshared_helpdesk,true,S-1-5-21-1-2-3-1100\n")
        zf.writestr("groups.csv", "SamAccountName,Name,SID\nGG,GG,S-1-5-21-1-2-3-2200\n")
        zf.writestr("memberships.csv", "Group,GroupSID,Member,MemberSID,MemberType\n")
    shared = import_ad_zip(old, classification_rules=rules)
    assert shared.identities[0].type == IdentityType.SHARED_ACCOUNT


def test_manifest_validation_rejects_unsupported_values_and_error_mismatch(tmp_path: Path) -> None:
    unsupported = tmp_path / "unsupported.zip"
    with ZipFile(unsupported, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.yaml", "schema_version: 99\nsource_type: active_directory\nprovider: corp-ad\ncompleteness: full\n")
        zf.writestr("users.csv", "SamAccountName,Enabled,SID\n")
        zf.writestr("groups.csv", "SamAccountName,Name,SID\n")
        zf.writestr("memberships.csv", "Group,GroupSID,Member,MemberSID,MemberType\n")
    with pytest.raises(ValueError):
        import_ad_zip(unsupported)

    mismatch = tmp_path / "mismatch.zip"
    with ZipFile(mismatch, "w", ZIP_DEFLATED) as zf:
        zf.writestr(
            "manifest.yaml",
            "schema_version: 1\nsource_type: active_directory\nprovider: corp-ad\ncompleteness: unknown\nstatistics:\n  collection_errors: 1\n",
        )
        zf.writestr("users.csv", "SamAccountName,Enabled,SID\n")
        zf.writestr("groups.csv", "SamAccountName,Name,SID\n")
        zf.writestr("memberships.csv", "Group,GroupSID,Member,MemberSID,MemberType\n")
        zf.writestr("collection-errors.csv", "ObjectType,ObjectIdentifier,ObjectSID,Operation,ErrorCode,ErrorMessage\n")
    with pytest.raises(ValueError):
        import_ad_zip(mismatch)


def test_zip_bomb_declared_uncompressed_size_is_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "bomb.zip"
    with ZipFile(archive, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.yaml", "provider: corp-ad\ncompleteness: full\n")
        zf.writestr("users.csv", "SamAccountName,Enabled,SID\n")
        zf.writestr("groups.csv", "SamAccountName,Name,SID\n")
        zf.writestr("memberships.csv", "0" * 25_000_001)
    with pytest.raises(ValueError):
        import_ad_zip(archive)
