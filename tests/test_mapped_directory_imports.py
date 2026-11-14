from __future__ import annotations

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from aurora.collector_runner import build_command
from aurora.domain import ExpectedAccessModel, GoldenSource, FunctionalModelCompleteness
from aurora.importers.ad import import_ad_zip
from aurora.importers.openldap import import_openldap_ldif
from aurora.services import create_golden_version, create_snapshot, promote_snapshot
from aurora.source_mapping import BUSINESS_CONTEXT_METADATA_KEY


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


def test_ad_sage_mapping_survives_snapshot_and_golden_v2_without_inventing_rights(tmp_path: Path) -> None:
    archive = tmp_path / "ad-sage-v2.zip"
    with ZipFile(archive, "w", ZIP_DEFLATED) as output:
        output.writestr("manifest.yaml", "provider: corp-ad\ncompleteness: full\n")
        output.writestr("users.csv", "SamAccountName,DisplayName,Enabled,SID\nalice,Alice,true,SID-U1\n")
        output.writestr(
            "groups.csv",
            "SamAccountName,Name,SID,extensionAttribute5,extensionAttribute6,extensionAttribute7\n"
            "GG_SAGE_RW,GG_SAGE_RW,SID-G1,Sage,ReadWrite,Invoices\n",
        )
        output.writestr(
            "memberships.csv",
            "Group,GroupSID,Member,MemberSID,MemberType\nGG_SAGE_RW,SID-G1,alice,SID-U1,user\n",
        )

    result = import_ad_zip(archive, source_config=_mapping())
    snapshot = create_snapshot(
        [result.provider], result.identities, [], result.accesses, result.assignments,
        [result.batch.id], import_scope=result.batch.scope,
        access_relations=result.access_relations,
    )
    promoted = promote_snapshot(GoldenSource("ad-sage"), snapshot)
    access = next(item for item in snapshot.accesses if item.name == "GG_SAGE_RW:member")
    mapped = access.metadata[BUSINESS_CONTEXT_METADATA_KEY]
    assert any(item.identity_identifier == "alice" for item in promoted.assignments)
    assert any(item.access_name == "GG_SAGE_RW:member" and item.access_permission == "member" for item in promoted.assignments)
    assert mapped["application"]["value"] == "Sage"
    assert mapped["business_permission"]["value"] == "ReadWrite"
    assert mapped["resource"]["value"] == "Invoices"
    assert promoted.functional_access_models == []

    golden_source = GoldenSource("ad-sage")
    v2 = create_golden_version(
        golden_source, promoted.assignments, "snapshot", schema_version=2,
        expected_access_definitions=[access],
        functional_access_models=[ExpectedAccessModel(
            "corp-ad", "GG_SAGE_RW:member", FunctionalModelCompleteness.NOT_DEFINED, ()
        )],
    )
    evolved = create_golden_version(
        golden_source, v2.assignments, "snapshot", [v2], schema_version=v2.schema_version,
        expected_access_definitions=v2.expected_access_definitions,
        expected_access_relations=v2.expected_access_relations,
        functional_access_models=v2.functional_access_models,
        access_comments=v2.access_comments,
    )
    assert evolved.functional_access_models == v2.functional_access_models
    assert evolved.expected_access_definitions[0].permission.identifier == "member"


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
    assert environment["AURORA_EXTRA_GROUP_ATTRIBUTES"] == "extensionAttribute5,extensionAttribute6,extensionAttribute7"
