from __future__ import annotations

from pathlib import Path

from access_review_engine.domain import IdentityType
from access_review_engine.importers.openldap import import_openldap_ldif


def test_openldap_26_ldapsearch_lll_group_variants(tmp_path: Path) -> None:
    ldif = tmp_path / "ldapsearch-lll.ldif"
    ldif.write_text(
        """
dn: uid=alice,ou=people,dc=example,dc=org
objectClass: inetOrgPerson
uid: alice
cn: Alice Example
mail: alice@example.org
description: Sales approver

dn: uid=bob,ou=people,dc=example,dc=org
objectClass: inetOrgPerson
uid: bob
cn: Bob Example
mail: bob@example.org

dn: cn=crm-readers,ou=groups,dc=example,dc=org
objectClass: groupOfNames
cn: crm-readers
description: CRM readers
member: uid=alice,ou=people,dc=example,dc=org
member: uid=bob,ou=people,dc=example,dc=org

dn: cn=finance-approvers,ou=groups,dc=example,dc=org
objectClass: groupOfUniqueNames
cn: finance-approvers
description: Finance approvers
uniqueMember: uid=alice,ou=people,dc=example,dc=org

dn: cn=linux-admins,ou=groups,dc=example,dc=org
objectClass: posixGroup
cn: linux-admins
gidNumber: 10001
memberUid: alice
""".strip(),
        encoding="utf-8",
    )

    result = import_openldap_ldif(ldif, "openldap-prod")

    assert {identity.identifier for identity in result.identities} >= {"alice", "bob"}
    assert {identity.display_name for identity in result.identities if identity.type == IdentityType.GROUP} == {
        "crm-readers",
        "finance-approvers",
        "linux-admins",
    }
    assert {access.display_name for access in result.accesses} == {
        "crm-readers:member",
        "finance-approvers:member",
        "linux-admins:member",
    }
    assert len(result.assignments) == 4
    assert {assignment.identity_identifier for assignment in result.assignments} == {"alice", "bob"}


def test_openldap_26_slapcat_operational_attributes_and_lowercase_objectclass(tmp_path: Path) -> None:
    ldif = tmp_path / "slapcat.ldif"
    ldif.write_text(
        """
dn: dc=example,dc=org
objectclass: dcObject
objectclass: organization
dc: example
o: Example Organization
structuralObjectClass: organization
entryUUID: 2134b714-e3a1-102c-9a15-f96ee263886d
createTimestamp: 20260128142643Z
entryCSN: 20260128142643.661124Z#000000#000#000000

dn: uid=carol,ou=people,dc=example,dc=org
objectclass: inetOrgPerson
uid: carol
cn: Carol Example
entryUUID: 11111111-2222-3333-4444-555555555555

dn: cn=ops,ou=groups,dc=example,dc=org
objectclass: groupOfNames
cn: ops
entryUUID: 99999999-8888-7777-6666-555555555555
member: uid=carol,ou=people,dc=example,dc=org
""".strip(),
        encoding="utf-8",
    )

    result = import_openldap_ldif(ldif, "openldap-prod")
    identities = {identity.identifier: identity for identity in result.identities}
    assert identities["entry:11111111-2222-3333-4444-555555555555"].native_id == "11111111-2222-3333-4444-555555555555"
    assert identities["group:99999999-8888-7777-6666-555555555555"].native_id == "99999999-8888-7777-6666-555555555555"
    assert result.assignments[0].identity_identifier == "entry:11111111-2222-3333-4444-555555555555"


def test_openldap_ldif_continuation_attribute_options_and_base64_values(tmp_path: Path) -> None:
    ldif = tmp_path / "options-and-base64.ldif"
    ldif.write_text(
        """
dn: uid=diane,ou=people,dc=example,dc=org
objectClass: inetOrgPerson
uid: diane
cn;lang-en: Diane Example
description: First line
 second line
mail: diane@example.org

dn: cn=reporting,ou=groups,dc=example,dc=org
objectClass: groupOfNames
cn:: cmVwb3J0aW5n
# comment from ldapsearch output
description: Reporting users
member: uid=diane,ou=people,dc=example,dc=org
""".strip(),
        encoding="utf-8",
    )

    result = import_openldap_ldif(ldif, "openldap-prod")
    identities = {identity.identifier: identity for identity in result.identities}
    assert identities["diane"].display_name == "Diane Example"
    assert identities["diane"].description == "First linesecond line"
    assert "reporting:member" in {access.display_name for access in result.accesses}
    assert result.accesses[0].description == "Reporting users"


def test_openldap_preserves_nested_groups_without_flattening(tmp_path: Path) -> None:
    ldif = tmp_path / "nested.ldif"
    ldif.write_text(
        """
dn: uid=erin,ou=people,dc=example,dc=org
objectClass: inetOrgPerson
uid: erin
cn: Erin Example

dn: cn=team-a,ou=groups,dc=example,dc=org
objectClass: groupOfNames
cn: team-a
member: uid=erin,ou=people,dc=example,dc=org

dn: cn=all-staff,ou=groups,dc=example,dc=org
objectClass: groupOfNames
cn: all-staff
member: cn=team-a,ou=groups,dc=example,dc=org
""".strip(),
        encoding="utf-8",
    )

    result = import_openldap_ldif(ldif, "openldap-prod")
    group_identities = {identity.display_name for identity in result.identities if identity.type == IdentityType.GROUP}
    assert group_identities == {"team-a", "all-staff"}
    access_by_display = {access.display_name: access.name for access in result.accesses}
    group_by_display = {identity.display_name: identity.identifier for identity in result.identities if identity.type == IdentityType.GROUP}
    assignments = {(assignment.access_name, assignment.identity_identifier) for assignment in result.assignments}
    assert (access_by_display["team-a:member"], "erin") in assignments
    assert (access_by_display["all-staff:member"], group_by_display["team-a"]) in assignments
    assert (access_by_display["all-staff:member"], "erin") not in assignments


def test_openldap_ignores_unused_binary_base64_attribute(tmp_path: Path) -> None:
    ldif = tmp_path / "binary.ldif"
    ldif.write_text(
        """
dn: uid=bin,ou=people,dc=example,dc=org
objectClass: inetOrgPerson
uid: bin
cn: Binary User
jpegPhoto:: //79

dn: cn=readers,ou=groups,dc=example,dc=org
objectClass: groupOfNames
cn: readers
member: uid=bin,ou=people,dc=example,dc=org
""".strip(),
        encoding="utf-8",
    )
    result = import_openldap_ldif(ldif, "openldap-prod")
    assert len(result.assignments) == 1


def test_openldap_ldif_change_records_are_rejected(tmp_path: Path) -> None:
    import pytest

    ldif = tmp_path / "change.ldif"
    ldif.write_text("dn: uid=alice,dc=example,dc=org\nchangetype: modify\nreplace: cn\ncn: Alice\n", encoding="utf-8")
    with pytest.raises(ValueError):
        import_openldap_ldif(ldif, "openldap-prod")
    ldif.write_text("dn: uid=alice,dc=example,dc=org\nchangetype: delete\n", encoding="utf-8")
    with pytest.raises(ValueError):
        import_openldap_ldif(ldif, "openldap-prod")
