from __future__ import annotations

import csv
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from access_review_engine.domain import IdentityStatus, IdentityType
from access_review_engine.importers.ad import import_ad_zip
from access_review_engine.services import reconcile_identities


def test_recent_ad_extract_preserves_direct_nested_memberships(tmp_path: Path) -> None:
    result = import_ad_zip(_fabrikam_like_zip(tmp_path))

    groups = {identity.identifier: identity for identity in result.identities if identity.type == IdentityType.GROUP}
    assert groups["Administrators"].native_id == "S-1-5-32-544"
    assert groups["Administrators"].description == "Built-in administrators"

    assignments = {
        (assignment.access_name, assignment.identity_identifier, assignment.origin.source)
        for assignment in result.assignments
    }
    assert ("Administrators:member", "Domain Admins", "Administrators") in assignments
    assert ("Domain Admins:member", "alice.admin", "Domain Admins") in assignments
    assert ("Administrators:member", "alice.admin", "Administrators") not in assignments


def test_recent_ad_extract_maps_disabled_accounts_and_optional_descriptions(tmp_path: Path) -> None:
    result = import_ad_zip(_fabrikam_like_zip(tmp_path))
    identities = {identity.identifier: identity for identity in result.identities}
    assert identities["mike"].status == IdentityStatus.ACTIVE
    assert identities["disabled.user"].status == IdentityStatus.DISABLED
    assert identities["disabled.user"].description is None
    assert identities["mike"].metadata["last_logon_date"] == "2025-01-14T05:10:16"


def test_ad_sid_reconciliation_keeps_internal_identity_on_rename() -> None:
    existing = [_identity("corp-ad", "jean.dupont", "S-1-5-21-123", IdentityStatus.ACTIVE)]
    imported = [_identity("corp-ad", "jdupont", "S-1-5-21-123", IdentityStatus.ACTIVE)]
    merged = reconcile_identities(existing, imported, completeness="full", scope={"type": "all"})
    assert len(merged) == 1
    assert merged[0].identifier == "jdupont"
    assert merged[0].id == existing[0].id


def test_full_import_marks_absent_identity_deleted_but_scoped_import_does_not() -> None:
    existing = [_identity("corp-ad", "old.user", "S-1-5-21-999", IdentityStatus.ACTIVE)]
    assert reconcile_identities(existing, [], completeness="full", scope={"type": "all"})[0].status == "deleted"
    assert reconcile_identities(
        existing,
        [],
        completeness="scoped",
        scope={"type": "accesses", "values": ["GG_FINANCE"]},
    ) == []



def test_multiple_recent_ad_extract_shapes_are_reliably_normalized(tmp_path: Path) -> None:
    archives = [
        _variant_zip(
            tmp_path,
            "finance-ad.zip",
            "finance-ad",
            [
                {
                    "SamAccountName": "ChewDavid",
                    "UserPrincipalName": "",
                    "DisplayName": "Chew David",
                    "Mail": "",
                    "Enabled": "False",
                    "SID": "S-1-5-21-2889043008-4136710315-2444824263-3544",
                    "DistinguishedName": "CN=Chew David,OU=NorthAmerica,OU=Sales,OU=UserAccounts,DC=FABRIKAM,DC=COM",
                    "LastLogonDate": "",
                    "PasswordLastSet": "",
                    "AccountExpirationDate": "",
                    "WhenCreated": "2024-05-10T10:00:00",
                    "Description": "",
                }
            ],
            [
                {
                    "SamAccountName": "AccountLeads",
                    "Name": "AccountLeads",
                    "SID": "S-1-5-21-41432690-3719764436-1984117282-1117",
                    "DistinguishedName": "CN=AccountLeads,OU=AccountDeptOU,DC=AppNC",
                    "Description": "",
                    "GroupScope": "DomainLocal",
                    "GroupCategory": "Distribution",
                }
            ],
            [
                {
                    "Group": "AccountLeads",
                    "GroupSID": "S-1-5-21-41432690-3719764436-1984117282-1117",
                    "Member": "ChewDavid",
                    "MemberSID": "S-1-5-21-2889043008-4136710315-2444824263-3544",
                    "MemberType": "user",
                    "MemberDN": "CN=Chew David,OU=NorthAmerica,OU=Sales,OU=UserAccounts,DC=FABRIKAM,DC=COM",
                }
            ],
        ),
        _variant_zip(
            tmp_path,
            "svc-ad.zip",
            "svc-ad",
            [
                {
                    "SamAccountName": "SQL01",
                    "UserPrincipalName": "SQL01@contoso.com",
                    "DisplayName": "SQL01 SvcAccount",
                    "Mail": "",
                    "Enabled": "True",
                    "SID": "S-1-5-21-200-200-200-1001",
                    "DistinguishedName": "CN=SQL01 SvcAccount,CN=Users,DC=contoso,DC=com",
                    "LastLogonDate": "2025-03-01T08:30:00",
                    "PasswordLastSet": "2025-02-01T08:30:00",
                    "AccountExpirationDate": "",
                    "WhenCreated": "2024-09-01T08:30:00",
                    "Description": "SQL service account",
                },
                {
                    "SamAccountName": "SQL02",
                    "UserPrincipalName": "SQL02@contoso.com",
                    "DisplayName": "SQL02 SvcAccount",
                    "Mail": "",
                    "Enabled": "True",
                    "SID": "S-1-5-21-200-200-200-1002",
                    "DistinguishedName": "CN=SQL02 SvcAccount,CN=Users,DC=contoso,DC=com",
                    "LastLogonDate": "2025-03-02T08:30:00",
                    "PasswordLastSet": "2025-02-01T08:30:00",
                    "AccountExpirationDate": "",
                    "WhenCreated": "2024-09-01T08:30:00",
                    "Description": "SQL service account",
                },
            ],
            [
                {
                    "SamAccountName": "SvcAccPSOGroup",
                    "Name": "SvcAccPSOGroup",
                    "SID": "S-1-5-21-200-200-200-2001",
                    "DistinguishedName": "CN=SvcAccPSOGroup,CN=Users,DC=contoso,DC=com",
                    "Description": "Password settings service accounts",
                    "GroupScope": "Global",
                    "GroupCategory": "Security",
                }
            ],
            [
                {
                    "Group": "SvcAccPSOGroup",
                    "GroupSID": "S-1-5-21-200-200-200-2001",
                    "Member": "SQL01",
                    "MemberSID": "S-1-5-21-200-200-200-1001",
                    "MemberType": "user",
                    "MemberDN": "CN=SQL01 SvcAccount,CN=Users,DC=contoso,DC=com",
                },
                {
                    "Group": "SvcAccPSOGroup",
                    "GroupSID": "S-1-5-21-200-200-200-2001",
                    "Member": "SQL02",
                    "MemberSID": "S-1-5-21-200-200-200-1002",
                    "MemberType": "user",
                    "MemberDN": "CN=SQL02 SvcAccount,CN=Users,DC=contoso,DC=com",
                },
            ],
        ),
    ]

    imported = [import_ad_zip(archive) for archive in archives]
    assert [item.provider.name for item in imported] == ["finance-ad", "svc-ad"]
    assert imported[0].identities[0].status == IdentityStatus.DISABLED
    assert imported[0].accesses[0].description is None
    assert len(imported[1].assignments) == 2
    assert {assignment.identity_identifier for assignment in imported[1].assignments} == {"SQL01", "SQL02"}
    assert imported[1].accesses[0].control_object.metadata == {}


def _fabrikam_like_zip(tmp_path: Path) -> Path:
    archive = tmp_path / "fabrikam-ad-export.zip"
    users = tmp_path / "users.csv"
    groups = tmp_path / "groups.csv"
    memberships = tmp_path / "memberships.csv"
    _write_csv(
        users,
        [
            {
                "SamAccountName": "mike",
                "UserPrincipalName": "mike@fabrikam.com",
                "DisplayName": "Mike F. Robbins",
                "Mail": "mike@fabrikam.com",
                "Enabled": "True",
                "SID": "S-1-5-21-611971124-518002951-3581791498-1105",
                "DistinguishedName": "CN=Mike F. Robbins,CN=Users,DC=fabrikam,DC=com",
                "LastLogonDate": "2025-01-14T05:10:16",
                "PasswordLastSet": "2025-01-01T09:00:00",
                "AccountExpirationDate": "",
                "WhenCreated": "2024-01-12T08:00:00",
                "Description": "Example user account",
            },
            {
                "SamAccountName": "alice.admin",
                "UserPrincipalName": "alice.admin@fabrikam.com",
                "DisplayName": "Alice Admin",
                "Mail": "",
                "Enabled": "True",
                "SID": "S-1-5-21-611971124-518002951-3581791498-1200",
                "DistinguishedName": "CN=Alice Admin,CN=Users,DC=fabrikam,DC=com",
                "LastLogonDate": "",
                "PasswordLastSet": "",
                "AccountExpirationDate": "",
                "WhenCreated": "2024-01-12T08:00:00",
                "Description": "",
            },
            {
                "SamAccountName": "disabled.user",
                "UserPrincipalName": "disabled.user@fabrikam.com",
                "DisplayName": "Disabled User",
                "Mail": "disabled.user@fabrikam.com",
                "Enabled": "False",
                "SID": "S-1-5-21-611971124-518002951-3581791498-1300",
                "DistinguishedName": "CN=Disabled User,CN=Users,DC=fabrikam,DC=com",
                "LastLogonDate": "",
                "PasswordLastSet": "",
                "AccountExpirationDate": "",
                "WhenCreated": "2024-01-12T08:00:00",
                "Description": "",
            },
        ],
    )
    _write_csv(
        groups,
        [
            {
                "SamAccountName": "Administrators",
                "Name": "Administrators",
                "SID": "S-1-5-32-544",
                "DistinguishedName": "CN=Administrators,CN=Builtin,DC=Fabrikam,DC=com",
                "Description": "Built-in administrators",
                "GroupScope": "DomainLocal",
                "GroupCategory": "Security",
            },
            {
                "SamAccountName": "Domain Admins",
                "Name": "Domain Admins",
                "SID": "S-1-5-21-611971124-518002951-3581791498-512",
                "DistinguishedName": "CN=Domain Admins,CN=Users,DC=Fabrikam,DC=com",
                "Description": "Domain administrators",
                "GroupScope": "Global",
                "GroupCategory": "Security",
            },
        ],
    )
    _write_csv(
        memberships,
        [
            {
                "Group": "Administrators",
                "GroupSID": "S-1-5-32-544",
                "Member": "Domain Admins",
                "MemberSID": "S-1-5-21-611971124-518002951-3581791498-512",
                "MemberType": "group",
                "MemberDN": "CN=Domain Admins,CN=Users,DC=Fabrikam,DC=com",
            },
            {
                "Group": "Domain Admins",
                "GroupSID": "S-1-5-21-611971124-518002951-3581791498-512",
                "Member": "alice.admin",
                "MemberSID": "S-1-5-21-611971124-518002951-3581791498-1200",
                "MemberType": "user",
                "MemberDN": "CN=Alice Admin,CN=Users,DC=Fabrikam,DC=com",
            },
        ],
    )
    with ZipFile(archive, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.yaml", "provider: corp-ad\ncompleteness: full\n")
        zf.write(users, "users.csv")
        zf.write(groups, "groups.csv")
        zf.write(memberships, "memberships.csv")
    return archive


def _write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _identity(provider: str, identifier: str, sid: str, status: str):
    from access_review_engine.domain import Identity

    return Identity(
        provider=provider,
        identifier=identifier,
        native_id=sid,
        type=IdentityType.USER_ACCOUNT,
        status=status,
    )



def _variant_zip(
    tmp_path: Path,
    filename: str,
    provider: str,
    users: list[dict[str, str]],
    groups: list[dict[str, str]],
    memberships: list[dict[str, str]],
) -> Path:
    archive = tmp_path / filename
    users_path = tmp_path / f"{filename}-users.csv"
    groups_path = tmp_path / f"{filename}-groups.csv"
    memberships_path = tmp_path / f"{filename}-memberships.csv"
    _write_csv(users_path, users)
    _write_csv(groups_path, groups)
    _write_csv(memberships_path, memberships)
    with ZipFile(archive, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.yaml", f"provider: {provider}\ncompleteness: full\n")
        zf.write(users_path, "users.csv")
        zf.write(groups_path, "groups.csv")
        zf.write(memberships_path, "memberships.csv")
    return archive
