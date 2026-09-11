from __future__ import annotations

import csv
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from access_review_engine.domain import Campaign, DecisionValue, OwnerRef
from access_review_engine.importers.ad import import_ad_zip
from access_review_engine.importers.openldap import import_openldap_ldif
from access_review_engine.reporting import build_report_rows, render_access_matrix, render_html_report, write_reports
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
    assert {access.display_name for access in result.accesses} == {"crm:member", "ops:member"}
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
    assert "Access Review Report - q1" in html
    assert "Golden Source" in html
    assert "none" in html
    assert "Vue d’ensemble" in html
    assert "Visualisations" in html
    assert "Findings" in html
    assert "Par service / accès" in html
    assert "filter-search" in html
    assert "filter-service" in html
    assert "filter-classification" in html
    assert "filter-decision" in html
    assert "filter-finding" in html
    assert "filter-status" in html
    assert "filter-reviewer" in html
    assert "Only anomalies" in html
    assert "Reset filters" in html
    assert "GG_CRM:member" in html
    assert "Native description" not in html
    assert "CRM access" in html
    fallback_row = _report_row(identity="bob", service="CRM", access="CRM-Admin", classification="unexpected", expected="no", observed="yes", decision="pending", findings="")
    fallback_row["issue"] = "Observed access not expected"
    fallback_html = render_html_report(Campaign("finding-table", "snapshot-1"), [fallback_row])
    assert "Observed access not expected" in fallback_html

    out = tmp_path / "reports"
    write_reports(out, campaign, items, decisions)
    assert (out / "campaign-report.html").exists()
    assert (out / "campaign-results.csv").exists()
    assert (out / "campaign-results.json").exists()



def test_html_report_handles_empty_campaign_with_premium_sections() -> None:
    html = render_html_report(Campaign("empty", "snapshot-1"), [])
    assert "No provider" in html
    assert "Access Review Outcome" in html
    assert "No data" in html
    assert "No matching rows." in html
    assert "kpi-groups" in html
    assert "charts-grid" in html


def test_html_report_premium_controls_and_findings_are_defined() -> None:
    campaign = Campaign("premium", "snapshot-1", status="open", display_name="Premium Review")
    rows = [
        _report_row(
            identity="alice",
            service="CRM-Sales",
            access="CRM-Sales",
            classification="expected_and_observed",
            expected="yes",
            observed="yes",
            decision="approve",
            findings="",
            comment=None,
        ),
        _report_row(
            identity="bob",
            service="CRM-Admin",
            access="CRM-Admin",
            classification="unexpected",
            expected="no",
            observed="yes",
            decision="revoke",
            findings="disabled_with_access, technical_account_without_owner",
            identity_status="disabled",
        ),
        _report_row(
            identity="carol",
            service="CRM-Support",
            access="CRM-Support",
            classification="missing",
            expected="yes",
            observed="no",
            decision="pending",
            findings="shared_account_without_owner",
        ),
        _report_row(
            identity="dan",
            service="CRM-Compta",
            access="CRM-Compta",
            classification="unknown_due_to_scope",
            expected="no",
            observed="yes",
            decision="not_applicable",
            findings="collection_incomplete",
        ),
    ]

    html = render_html_report(campaign, rows)

    assert "Premium Review" in html
    assert "Access Review Outcome" in html
    assert "Review Decisions" in html
    assert "Accesses by service / role" in html
    assert "No findings" in html
    assert "Disabled user with access" in html
    assert "Technical account without owner" in html
    assert "Shared account without owner" in html
    assert "Unknown due to scope" in html
    assert "filter-anomalies" in html
    assert "sortFields" in html
    assert "identity_status" in html
    assert "aria-expanded" in html
    assert "service-card" in html
    assert "donutChart" in html
    assert "barChart" in html
    assert "innerHTML" not in html
    assert "undefined" not in html
    assert ">null<" not in html
    assert "None" not in html



def test_authentication_policy_is_explicit_and_secret_free(tmp_path: Path) -> None:
    rows = [
        _report_row(identity="alice", service="CRM", access="CRM-Sales", classification="expected_and_observed", expected="yes", observed="yes", decision="approve", findings=""),
        _report_row(identity="bob", service="CRM", access="CRM-Admin", classification="expected_and_observed", expected="yes", observed="yes", decision="approve", findings=""),
    ]
    rows[0]["authentication"] = {
        "authentication_method": "Password + SSO",
        "mfa_requirement": "Required",
        "mfa_methods": ["TOTP", "FIDO2"],
        "password_policy": {"minimum_length": 14, "history": 12},
        "token_policy": {"expiration": "90 days", "token_value": "do-not-render"},
        "authentication_status": "Compliant",
    }
    rows[0]["provider"] = "openldap-corp"
    rows[1]["provider"] = "entra-corp"

    html = render_html_report(Campaign("auth", "snapshot-1"), rows)
    assert html.index("Authentication Posture") < html.index("Visualisations")
    assert "Password + SSO" in html
    assert "Required" in html
    assert "TOTP, FIDO2" in html
    assert "Minimum_length" not in html
    assert "Minimum Length: 14" in html
    assert "Compliant" in html
    assert "Not collected" in html
    assert "do-not-render" not in html

    matrix_path = tmp_path / "role-permissions.csv"
    _write_csv(matrix_path, [{"role": "CRM-Admin", "resource": "invoices", "permission": "write"}])
    matrix = render_access_matrix(matrix_path, [{"provider": "openldap-corp", "authentication": "Password", **{key: "Not collected" for key in ("password", "password_policy", "mfa", "mfa_methods", "sso", "tokens", "token_policy", "session_policy", "local_authentication", "status")}}])
    assert matrix.index("01 — Authentication Policy") < matrix.index("02 — Golden Access Matrix")
    assert "openldap-corp" in matrix
    assert "CRM-Admin" in matrix


def test_campaign_csv_report_neutralizes_spreadsheet_formulas(tmp_path: Path) -> None:
    formula = '=HYPERLINK("https://example.invalid","x")'
    campaign = Campaign("formula", "snapshot-1")
    from access_review_engine.domain import ReviewItem

    item = ReviewItem(
        campaign_id="campaign-1",
        identity_provider="corp-ad",
        identity_identifier=formula,
        identity_status="active",
        access_provider="corp-ad",
        access_name="+APP_ADMIN",
        control_object={"type": "group", "identifier": "@group", "display_name": "@group"},
        permission={"identifier": "member", "display_name": "Member"},
        target=None,
        description="-dangerous description",
        origin=None,
        expected=False,
        observed=True,
        classification="unexpected",
        findings=[],
        account_owner=None,
        access_owner=None,
        reviewer=None,
    )
    decision = create_decision(item, DecisionValue.REVOKE, "-remove", "reviewer")
    out = tmp_path / "reports"
    write_reports(out, campaign, [item], [decision])

    with (out / "campaign-results.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    row = rows[0]
    assert row["identity"] == "'" + formula
    assert row["access"] == "'+APP_ADMIN"
    assert row["control_object"] == "'@group"
    assert row["description"] == "'-dangerous description"
    assert row["comment"] == "'-remove"
    json_report = (out / "campaign-results.json").read_text(encoding="utf-8")
    assert "HYPERLINK" in json_report
    assert "'=HYPERLINK" not in json_report


def _report_row(
    *,
    identity: str,
    service: str,
    access: str,
    classification: str,
    expected: str,
    observed: str,
    decision: str,
    findings: str,
    identity_status: str = "active",
    comment: str | None = "reviewed",
) -> dict[str, object]:
    return {
        "owner": "corp-ad/reviewer",
        "service": service,
        "component": "",
        "provider": "corp-ad",
        "control_object_type": "group",
        "control_object": access,
        "permission": "member",
        "access": access,
        "description": "",
        "identity": identity,
        "identity_provider": "corp-ad",
        "identity_status": identity_status,
        "expected": expected,
        "observed": observed,
        "classification": classification,
        "findings": findings,
        "issue": findings,
        "decision": decision,
        "reviewer": "corp-ad/reviewer",
        "comment": comment,
    }


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
