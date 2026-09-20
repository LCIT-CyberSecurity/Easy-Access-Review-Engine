from __future__ import annotations

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from access_review_engine.collector_runner import build_command
from access_review_engine.importers.ad import import_ad_zip
from access_review_engine.importers.openldap import import_openldap_ldif
from access_review_engine.source_mapping import BUSINESS_CONTEXT_METADATA_KEY


def _mapping() -> dict[str, object]:
    return {
        "business_mapping": {
            "application": {"mode": "attribute", "attribute": "extensionAttribute5"},
            "business_permission": {"mode": "attribute", "attribute": "extensionAttribute6"},
            "resource": {"mode": "attribute", "attribute": "extensionAttribute7"},
        }
    }


def test_ad_artifact_mapping_preserves_member_permission(tmp_path: Path) -> None:
    archive = tmp_path / "ad.zip"
    with ZipFile(archive, "w", ZIP_DEFLATED) as output:
        output.writestr("manifest.yaml", "provider: corp-ad\ncompleteness: full\n")
        output.writestr(
            "users.csv",
            "SamAccountName,DisplayName,Enabled,SID,DistinguishedName,Description\n"
            "alice,Alice,true,SID-U1,CN=Alice,\n",
        )
        output.writestr(
            "groups.csv",
            "SamAccountName,Name,SID,DistinguishedName,Description,GroupScope,GroupCategory,extensionAttribute5,extensionAttribute6,extensionAttribute7\n"
            "GG_SAGE_RW,GG_SAGE_RW,SID-G1,CN=GG_SAGE_RW,Finance,Global,Security,Sage,ReadWrite,Invoices\n",
        )
        output.writestr(
            "memberships.csv",
            "Group,GroupSID,Member,MemberSID,MemberType,MemberDN\n"
            "GG_SAGE_RW,SID-G1,alice,SID-U1,user,CN=Alice\n",
        )

    result = import_ad_zip(archive, source_config=_mapping())
    access = result.accesses[0]
    context = access.metadata[BUSINESS_CONTEXT_METADATA_KEY]
    assert access.permission.identifier == "member"
    assert context["application"]["value"] == "Sage"
    assert context["business_permission"]["value"] == "ReadWrite"
    assert context["resource"]["value"] == "Invoices"


def test_openldap_artifact_mapping_uses_only_present_optional_fields(tmp_path: Path) -> None:
    ldif = tmp_path / "directory.ldif"
    ldif.write_text(
        """dn: uid=alice,ou=people,dc=example,dc=test
objectClass: inetOrgPerson
uid: alice
cn: Alice

dn: cn=sage,ou=groups,dc=example,dc=test
objectClass: groupOfNames
cn: sage
entryUUID: group-1
extensionAttribute5: Sage
extensionAttribute6: ReadWrite
member: uid=alice,ou=people,dc=example,dc=test
""",
        encoding="utf-8",
    )
    result = import_openldap_ldif(ldif, "ldap-production", source_config=_mapping())
    access = result.accesses[0]
    context = access.metadata[BUSINESS_CONTEXT_METADATA_KEY]
    assert access.permission.identifier == "member"
    assert context["application"]["value"] == "Sage"
    assert context["business_permission"]["value"] == "ReadWrite"
    assert "resource" not in context


def test_collectors_request_configured_attributes_without_executable_interpolation(tmp_path: Path) -> None:
    ad = {
        "provider": "corp-ad",
        "type": "active_directory",
        "connection": {"server": "dc.example.test"},
        "collection": {},
        **_mapping(),
    }
    command, _ = build_command(ad, tmp_path / "ad.zip", tmp_path)
    assert "-AdditionalGroupProperties" in command
    assert command[command.index("-AdditionalGroupProperties") + 1] == "extensionAttribute5,extensionAttribute6,extensionAttribute7"

    ldap = {
        "provider": "ldap-production",
        "type": "openldap",
        "connection": {"uri": "ldaps://ldap.example.test", "base_dn": "dc=example,dc=test"},
        "collection": {},
        **_mapping(),
    }
    _, environment = build_command(ldap, tmp_path / "ldap.zip", tmp_path)
    assert environment["EXTRA_GROUP_ATTRIBUTES"] == "extensionAttribute5,extensionAttribute6,extensionAttribute7"
