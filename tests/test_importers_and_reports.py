from __future__ import annotations

import csv
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from access_review_engine.domain import Campaign, DecisionValue, OwnerRef
from access_review_engine.importers.ad import import_ad_zip
from access_review_engine.importers.openldap import import_openldap_ldif
from access_review_engine.reporting import build_report_rows, render_html_report, write_reports
from access_review_engine.services import create_decision, create_snapshot, open_campaign


def test_ad_zip_imports_users_groups_memberships_and_descriptions(tmp_path: Path) -> None:
    archive = _ad_zip(tmp_path)
    result = import_ad_zip(archive)
    assert result.provider.name == "corp-ad"
    assert {identity.identifier for identity in result.identities} >= {"jean.dupont", "GG_CRM"}
    assert result.accesses[0].description == "CRM access"
    assert result.assignments[0].identity_identifier == "jean.dupont"
    assert result.assignments[0].origin.source == "GG_CRM"


def test_ad_zip_rejects_missing_manifest_and_zip_slip(tmp_path: Path) -> None:
    bad = tmp_path / "bad.zip"
    with ZipFile(bad, "w", ZIP_DEFLATED) as zf:
        zf.writestr("../evil.csv", "x")
    with pytest.raises(ValueError):
        import_ad_zip(bad)

    missing = tmp_path / "missing.zip"
    with ZipFile(missing, "w", ZIP_DEFLATED) as zf:
        zf.writestr("users.csv", "")
    with pytest.raises(ValueError):
        import_ad_zip(missing)


def test_openldap_imports_supported_groups_and_members(tmp_path: Path) -> None:
    ldif = tmp_path / "directory.ldif"
    ldif.write_text(
        """
dn: uid=jean,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
uid: jean
cn: Jean Dupont
mail: jean@example.com
description: Sales user

dn: cn=crm,ou=groups,dc=example,dc=com
objectClass: groupOfNames
cn: crm
description: CRM access
member: uid=jean,ou=people,dc=example,dc=com

dn: cn=ops,ou=groups,dc=example,dc=com
objectClass: posixGroup
cn: ops
memberUid: jean
""".strip(),
        encoding="utf-8",
    )
    result = import_openldap_ldif(ldif, "internal-ldap")
    assert {access.name for access in result.accesses} == {"crm:member", "ops:member"}
    assert {assignment.identity_identifier for assignment in result.assignments} == {"jean"}


def test_html_report_treats_dynamic_values_as_text() -> None:
    payload = "<img src=x onerror=alert(1)>"
    campaign = Campaign("xss", "snapshot-1", display_name=payload)
    html = render_html_report(
        campaign,
        [
            {
                "owner": payload,
                "service": payload,
                "provider": "corp-ad",
                "classification": "unexpected",
                "decision": "pending",
                "access": payload,
                "identity": payload,
                "identity_provider": "corp-ad",
                "identity_status": "unknown",
                "expected": "no",
                "observed": "yes",
                "findings": payload,
                "reviewer": payload,
                "comment": payload,
            }
        ],
    )
    assert "<img src=x onerror=alert(1)>" not in html
    assert "\\u003cimg src=x onerror=alert(1)\\u003e" in html
    assert "textContent" in html
    assert "innerHTML" not in html


def test_html_report_contains_required_sections_and_filters(tmp_path: Path) -> None:
    result = import_ad_zip(_ad_zip(tmp_path))
    owner = OwnerRef("corp-ad", "jean.dupont")
    result.accesses[0].access_owner = owner
    snapshot = create_snapshot(
        [result.provider], result.identities, [], result.accesses, result.assignments, [result.batch.id]
    )
    campaign, items = open_campaign(Campaign("q1", snapshot.id, manager=owner), snapshot)
    decisions = [create_decision(items[0], DecisionValue.APPROVE, None, "jean.dupont")]
    rows = build_report_rows(items, decisions)
    html = render_html_report(campaign, rows)
    assert "Access Review - q1" in html
    assert "Golden Source version: none" in html
    assert "filter-owner" in html
    assert "filter-identity" in html
    assert "GG_CRM:member" in html
    assert "Native description" not in html
    assert "CRM access" in html

    out = tmp_path / "reports"
    write_reports(out, campaign, items, decisions)
    assert (out / "campaign-report.html").exists()
    assert (out / "campaign-results.csv").exists()
    assert (out / "campaign-results.json").exists()


def _ad_zip(tmp_path: Path) -> Path:
    archive = tmp_path / "corp-ad-export.zip"
    users = tmp_path / "users.csv"
    groups = tmp_path / "groups.csv"
    memberships = tmp_path / "memberships.csv"
    _write_csv(
        users,
        [
            {
                "SamAccountName": "jean.dupont",
                "UserPrincipalName": "jean.dupont@example.com",
                "DisplayName": "Jean Dupont",
                "Mail": "jean.dupont@example.com",
                "Enabled": "true",
                "SID": "SID-1",
                "DistinguishedName": "CN=Jean",
                "Description": "",
            }
        ],
    )
    _write_csv(
        groups,
        [
            {
                "SamAccountName": "GG_CRM",
                "Name": "GG_CRM",
                "SID": "SID-G",
                "DistinguishedName": "CN=GG_CRM",
                "Description": "CRM access",
                "GroupScope": "Global",
                "GroupCategory": "Security",
            }
        ],
    )
    _write_csv(
        memberships,
        [
            {
                "Group": "GG_CRM",
                "GroupSID": "SID-G",
                "Member": "jean.dupont",
                "MemberSID": "SID-1",
                "MemberType": "user",
                "MemberDN": "CN=Jean",
            }
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
