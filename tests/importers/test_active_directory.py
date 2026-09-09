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



def test_realistic_ad_locked_expired_smsa_and_csv_special_characters(tmp_path: Path) -> None:
    archive = tmp_path / "realistic-ad.zip"
    with ZipFile(archive, "w", ZIP_DEFLATED) as zf:
        zf.writestr(
            "manifest.yaml",
            "schema_version: 1\nsource_type: active_directory\nprovider: corp-ad\ncompleteness: full\nstatistics:\n  collection_errors: 0\n",
        )
        zf.writestr(
            "users.csv",
            'SamAccountName,UserPrincipalName,DisplayName,Mail,Enabled,SID,DistinguishedName,Description,PrimaryGroupID,LockedOut,ObjectGUID,AccountExpirationDate\n'
            'locked.user,locked@example.test,"Locked, User",locked@example.test,true,S-1-5-21-1-2-3-1101,"CN=Locked User,OU=Users,DC=corp,DC=example,DC=test",locked account,513,true,11111111-1111-1111-1111-111111111111,\n'
            'expired.user,expired@example.test,Expired User,expired@example.test,true,S-1-5-21-1-2-3-1102,"CN=Expired User,OU=Users,DC=corp,DC=example,DC=test",expired account,513,false,22222222-2222-2222-2222-222222222222,2000-01-01T00:00:00Z\n'
            'doe.john,john@example.test,"Doe, John",john@example.test,true,S-1-5-21-1-2-3-1103,"CN=Doe\\, John,OU=People,DC=corp,DC=example,DC=test","apostrophe '' comma, quote "" accent François 非ラテン",513,false,33333333-3333-3333-3333-333333333333,\n',
        )
        zf.writestr(
            "service_accounts.csv",
            'SamAccountName,Name,DisplayName,SID,DistinguishedName,Enabled,Description,ObjectClass,ObjectGUID,PrimaryGroupID,ServicePrincipalName\n'
            'smsa_sql$,smsa_sql$,smsa_sql$,S-1-5-21-1-2-3-2101,"CN=smsa_sql,CN=Managed Service Accounts,DC=corp,DC=example,DC=test",true,"sMSA with $, comma, and François",msDS-ManagedServiceAccount,44444444-4444-4444-4444-444444444444,513,MSSQLSvc/sql.example.test\n',
        )
        zf.writestr(
            "computers.csv",
            'SamAccountName,Name,SID,DistinguishedName,Enabled,DNSHostName,Description,ObjectGUID,PrimaryGroupID\n'
            'PC-SPECIAL$,PC-SPECIAL,S-1-5-21-1-2-3-3101,"CN=PC-SPECIAL,OU=Workstations,DC=corp,DC=example,DC=test",true,pc-special.example.test,"computer with $ and comma, ok",55555555-5555-5555-5555-555555555555,515\n',
        )
        zf.writestr(
            "groups.csv",
            'SamAccountName,Name,SID,DistinguishedName,Description,GroupScope,GroupCategory\n'
            'Domain Users,Domain Users,S-1-5-21-1-2-3-513,"CN=Domain Users,CN=Users,DC=corp,DC=example,DC=test",primary users,Global,Security\n'
            'Domain Computers,Domain Computers,S-1-5-21-1-2-3-515,"CN=Domain Computers,CN=Users,DC=corp,DC=example,DC=test",primary computers,Global,Security\n'
            'GG_SPECIAL,"GG, Special",S-1-5-21-1-2-3-2201,"CN=GG_SPECIAL,OU=Groups,DC=corp,DC=example,DC=test","group with quote "" and accent François",Global,Security\n',
        )
        zf.writestr(
            "memberships.csv",
            'Group,GroupSID,Member,MemberSID,MemberType,MemberDN,MembershipType\n'
            'GG_SPECIAL,S-1-5-21-1-2-3-2201,doe.john,S-1-5-21-1-2-3-1103,user,"CN=Doe\\, John,OU=People,DC=corp,DC=example,DC=test",direct\n'
            'GG_SPECIAL,S-1-5-21-1-2-3-2201,smsa_sql$,S-1-5-21-1-2-3-2101,msDS-ManagedServiceAccount,"CN=smsa_sql,CN=Managed Service Accounts,DC=corp,DC=example,DC=test",direct\n'
            'GG_SPECIAL,S-1-5-21-1-2-3-2201,PC-SPECIAL$,S-1-5-21-1-2-3-3101,computer,"CN=PC-SPECIAL,OU=Workstations,DC=corp,DC=example,DC=test",direct\n',
        )
        zf.writestr("collection-errors.csv", "ObjectType,ObjectIdentifier,ObjectSID,Operation,ErrorCode,ErrorMessage\n")

    result = import_ad_zip(archive)
    identities = {identity.identifier: identity for identity in result.identities}
    assert identities["locked.user"].metadata["locked_out"] is True
    assert identities["expired.user"].metadata["account_expired"] is True
    assert identities["smsa_sql$"].type == IdentityType.TECHNICAL_ACCOUNT
    assert identities["smsa_sql$"].metadata["managed_service_account_type"] == "msa"
    assert identities["doe.john"].display_name == "Doe, John"
    assert identities["doe.john"].metadata["distinguished_name"] == "CN=Doe\\, John,OU=People,DC=corp,DC=example,DC=test"
    assert "François" in (identities["doe.john"].description or "")
    assert identities["PC-SPECIAL$"].metadata["primary_group_id"] == "515"
    assignments = {(item.access_name, item.identity_identifier) for item in result.assignments}
    assert ("GG_SPECIAL:member", "doe.john") in assignments
    assert ("GG_SPECIAL:member", "smsa_sql$") in assignments
    assert ("GG_SPECIAL:member", "PC-SPECIAL$") in assignments

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


def test_enabled_status_distinguishes_true_false_unknown_and_missing(tmp_path: Path) -> None:
    archive = tmp_path / "enabled-values.zip"
    with ZipFile(archive, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.yaml", "provider: corp-ad\ncompleteness: full\n")
        zf.writestr(
            "users.csv",
            "SamAccountName,Enabled,SID\n"
            "active,true,S-1-5-21-1-2-3-1101\n"
            "disabled,false,S-1-5-21-1-2-3-1102\n"
            "empty,,S-1-5-21-1-2-3-1103\n"
            "invalid,not-a-bool,S-1-5-21-1-2-3-1104\n",
        )
        zf.writestr(
            "service_accounts.csv",
            "SamAccountName,Enabled,SID,ObjectClass\nsvc_active$,True,S-1-5-21-1-2-3-2101,msDS-GroupManagedServiceAccount\nsvc_unknown$,,S-1-5-21-1-2-3-2102,msDS-ManagedServiceAccount\n",
        )
        zf.writestr(
            "computers.csv",
            "SamAccountName,Enabled,SID,DNSHostName\npc_active$,True,S-1-5-21-1-2-3-3101,pc.example.test\npc_unknown$,bogus,S-1-5-21-1-2-3-3102,pc2.example.test\n",
        )
        zf.writestr("groups.csv", "SamAccountName,Name,SID\nGG,GG,S-1-5-21-1-2-3-2200\n")
        zf.writestr("memberships.csv", "Group,GroupSID,Member,MemberSID,MemberType\n")

    result = import_ad_zip(archive)
    identities = {identity.identifier: identity for identity in result.identities}
    assert identities["active"].status == IdentityStatus.ACTIVE
    assert identities["disabled"].status == IdentityStatus.DISABLED
    assert identities["empty"].status == IdentityStatus.UNKNOWN
    assert identities["invalid"].status == IdentityStatus.UNKNOWN
    assert identities["svc_active$"].status == IdentityStatus.ACTIVE
    assert identities["svc_unknown$"].status == IdentityStatus.UNKNOWN
    assert identities["pc_active$"].status == IdentityStatus.ACTIVE
    assert identities["pc_unknown$"].status == IdentityStatus.UNKNOWN


def test_missing_enabled_column_is_unknown(tmp_path: Path) -> None:
    archive = tmp_path / "missing-enabled.zip"
    with ZipFile(archive, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.yaml", "provider: corp-ad\ncompleteness: full\n")
        zf.writestr("users.csv", "SamAccountName,SID\nlegacy,S-1-5-21-1-2-3-1101\n")
        zf.writestr("groups.csv", "SamAccountName,Name,SID\nGG,GG,S-1-5-21-1-2-3-2200\n")
        zf.writestr("memberships.csv", "Group,GroupSID,Member,MemberSID,MemberType\nGG,S-1-5-21-1-2-3-2200,legacy,S-1-5-21-1-2-3-1101,user\n")

    result = import_ad_zip(archive)
    assert {identity.identifier: identity for identity in result.identities}["legacy"].status == IdentityStatus.UNKNOWN


def test_manifest_utf8_bom_is_supported(tmp_path: Path) -> None:
    archive = tmp_path / "bom.zip"
    with ZipFile(archive, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.yaml", "\ufeffprovider: corp-ad\ncompleteness: full\n")
        zf.writestr("users.csv", "SamAccountName,Enabled,SID\n")
        zf.writestr("groups.csv", "SamAccountName,Name,SID\n")
        zf.writestr("memberships.csv", "Group,GroupSID,Member,MemberSID,MemberType\n")

    assert import_ad_zip(archive).provider.name == "corp-ad"


def test_configurable_zip_limits_accept_large_memberships_and_reject_excessive(tmp_path: Path) -> None:
    accepted = tmp_path / "accepted-large.zip"
    with ZipFile(accepted, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.yaml", "provider: corp-ad\ncompleteness: full\n")
        zf.writestr("users.csv", "SamAccountName,Enabled,SID\n")
        zf.writestr("groups.csv", "SamAccountName,Name,SID\n")
        zf.writestr("memberships.csv", "Group,GroupSID,Member,MemberSID,MemberType\n" + "\n".join("GG,SID-G,missing,SID-M,user" for _ in range(5_000)))
    assert import_ad_zip(accepted, max_memberships_file_bytes=200_000).assignments == []

    rejected = tmp_path / "rejected-large.zip"
    with ZipFile(rejected, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.yaml", "provider: corp-ad\ncompleteness: full\n")
        zf.writestr("users.csv", "SamAccountName,Enabled,SID\n")
        zf.writestr("groups.csv", "SamAccountName,Name,SID\n")
        zf.writestr("memberships.csv", "Group,GroupSID,Member,MemberSID,MemberType\n" + "\n".join("GG,SID-G,missing,SID-M,user" for _ in range(5_000)))
    with pytest.raises(ValueError):
        import_ad_zip(rejected, max_memberships_file_bytes=100_000)


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
        import_ad_zip(archive, max_memberships_file_bytes=25_000_000)
