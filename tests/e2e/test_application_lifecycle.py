from __future__ import annotations

import csv
from io import StringIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from access_review_engine.application import import_file_to_repository
from access_review_engine.domain import Campaign, DecisionValue, Finding, OwnerRef
from access_review_engine.reporting import write_reports
from access_review_engine.services import (
    close_campaign,
    create_decision,
    create_golden_source,
    golden_diff,
    open_campaign,
    promote_campaign,
    promote_snapshot,
    remediation_from_decisions,
)
from access_review_engine.storage import Repository


def test_full_eare_application_lifecycle_from_import_to_report_and_golden(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "review.db")
    try:
        first_snapshot = import_file_to_repository(repo, _ad_lifecycle_zip(tmp_path, "n1", variant="baseline"))
        golden_source = create_golden_source("corp-baseline", "Corporate baseline")
        repo.upsert("golden_sources", golden_source)
        golden_v1 = promote_snapshot(golden_source, first_snapshot)
        repo.insert_append_only("golden_source_versions", golden_v1)

        second_snapshot = import_file_to_repository(
            repo,
            _ad_lifecycle_zip(tmp_path, "n2", variant="modified"),
            golden_version=golden_v1,
        )
        unknown_snapshot = import_file_to_repository(
            repo,
            _ad_lifecycle_zip(tmp_path, "n3", variant="unknown"),
            golden_version=golden_v1,
        )

        states = {
            (row["access_name"], row["identity_identifier"]): row
            for row in second_snapshot.comparison_states
        }
        assert states[("APP_READ:member", "alice")]["classification"] == "expected_and_observed"
        assert states[("APP_READ:member", "david.renamed")]["classification"] == "expected_and_observed"
        assert states[("APP_READ:member", "carol")]["classification"] == "missing"
        assert states[("APP_ADMIN:member", "bob")]["classification"] == "unexpected"
        assert Finding.DISABLED_WITH_ACCESS in states[("APP_ADMIN:member", "bob")]["findings"]
        assert states[("APP_ADMIN:member", "svc-batch$")]["classification"] == "unexpected"
        assert Finding.TECHNICAL_ACCOUNT_WITHOUT_OWNER in states[("APP_ADMIN:member", "svc-batch$")]["findings"]
        assert any(row["status"] == "deleted" and row["identifier"] == "eve" for row in repo.list_payloads("identities"))
        assert {row["classification"] for row in unknown_snapshot.comparison_states} <= {"unknown_due_to_scope", "unexpected"}
        assert any(Finding.COLLECTION_INCOMPLETE in row["findings"] for row in unknown_snapshot.comparison_states)

        campaign = Campaign(
            "q2-review",
            second_snapshot.id,
            golden_source_version_id=golden_v1.id,
            manager=OwnerRef("corp-ad", "manager"),
            default_reviewer=OwnerRef("corp-ad", "manager"),
        )
        opened, items = open_campaign(campaign, second_snapshot)
        repo.upsert("campaigns", opened)
        for item in items:
            repo.upsert("review_items", item)

        by_state = {(item.classification, item.access_name, item.identity_identifier): item for item in items}
        decisions = []
        for item in items:
            if item is by_state[("missing", "APP_READ:member", "carol")]:
                decisions.append(create_decision(item, DecisionValue.APPROVE, None, "manager"))
            elif item.access_name == "APP_AUDIT:member" and item.identity_identifier == "francois":
                decisions.append(create_decision(item, DecisionValue.REVOKE, "access no longer required", "manager"))
            elif item.classification == "unexpected":
                decisions.append(create_decision(item, DecisionValue.REVOKE, "not approved for this role", "manager"))
            else:
                decisions.append(create_decision(item, DecisionValue.APPROVE, None, "manager"))
        for decision in decisions:
            repo.insert_append_only("decisions", decision)

        closed = close_campaign(opened, items, decisions)
        repo.upsert("campaigns", closed)
        remediations = remediation_from_decisions(items, decisions)
        for remediation in remediations:
            repo.insert_append_only("remediation_actions", remediation)
        assert {action.action for action in remediations} == {"grant", "revoke"}
        assert sum(1 for action in remediations if action.action == "grant") == 1
        assert sum(1 for action in remediations if action.action == "revoke") >= 1

        reports = tmp_path / "reports"
        write_reports(reports, closed, items, decisions, golden_v1)
        assert (reports / "campaign-report.html").read_text(encoding="utf-8").count("q2-review") >= 1
        csv_report = (reports / "campaign-results.csv").read_text(encoding="utf-8")
        assert "missing" in csv_report
        assert "unexpected" in csv_report
        assert "revoke" in csv_report

        golden_v2 = promote_campaign(golden_source, closed, items, decisions, golden_v1)
        repo.insert_append_only("golden_source_versions", golden_v2)
        diff = golden_diff(golden_v1, golden_v2)
        assert any(row["status"] == "removed" and row["identity_identifier"] == "francois" for row in diff)
        assert any(row["status"] == "unchanged" and row["identity_identifier"] == "carol" for row in diff)
        assert not any(row["status"] == "added" and row["identity_identifier"] == "bob" for row in diff)
        persisted_snapshots = {row["id"]: row for row in repo.list_payloads("snapshots")}
        assert persisted_snapshots[unknown_snapshot.id]["source_import_ids"] == unknown_snapshot.source_import_ids
        assert len(repo.list_payloads("review_items")) == len(items)
        assert len(repo.list_payloads("decisions")) == len(decisions)
        assert len(repo.list_payloads("remediation_actions")) == len(remediations)
    finally:
        repo.close()


def _ad_lifecycle_zip(tmp_path: Path, name: str, variant: str) -> Path:
    archive = tmp_path / f"{name}.zip"
    users = [
        _user("manager", "S-1-5-21-100-200-300-1000", "Manager", enabled="true"),
        _user("alice", "S-1-5-21-100-200-300-1101", "Alice", enabled="true"),
        _user("bob", "S-1-5-21-100-200-300-1102", "Bob", enabled="false"),
        _user("carol", "S-1-5-21-100-200-300-1103", "Carol", enabled="true"),
        _user("dave", "S-1-5-21-100-200-300-1104", "Dave", enabled="true"),
        _user("eve", "S-1-5-21-100-200-300-1105", "Eve", enabled="true"),
        _user("francois", "S-1-5-21-100-200-300-1106", "François", enabled="true"),
        _user("li.wei", "S-1-5-21-100-200-300-1107", "李伟", enabled="true"),
        _user("maria", "S-1-5-21-100-200-300-1108", "María", enabled="true"),
        _user("noah", "S-1-5-21-100-200-300-1109", "Noah", enabled="true"),
        _user("olivia", "S-1-5-21-100-200-300-1110", "Olivia", enabled="true"),
    ]
    if variant in {"modified", "unknown"}:
        users = [(_user("david.renamed", "S-1-5-21-100-200-300-1104", "David Renamed", enabled="true") if row["SID"] == "S-1-5-21-100-200-300-1104" else row) for row in users]
        users = [row for row in users if row["SamAccountName"] != "eve"]
    groups = [
        _group("Domain Users", "S-1-5-21-100-200-300-513", "Primary users"),
        _group("APP_READ", "S-1-5-21-100-200-300-2201", "Read access"),
        _group("APP_ADMIN", "S-1-5-21-100-200-300-2202", "Admin access"),
        _group("APP_AUDIT", "S-1-5-21-100-200-300-2203", "Audit access"),
    ]
    service_accounts = [
        {
            "SamAccountName": "svc-batch$",
            "Name": "svc-batch$",
            "DisplayName": "svc-batch$",
            "SID": "S-1-5-21-100-200-300-3101",
            "DistinguishedName": "CN=svc-batch,CN=Managed Service Accounts,DC=corp,DC=example,DC=test",
            "Enabled": "true",
            "Description": "Batch service account",
            "ObjectClass": "msDS-ManagedServiceAccount",
            "ObjectGUID": "00000000-0000-0000-0000-000000003101",
            "PrimaryGroupID": "513",
            "ServicePrincipalName": "HTTP/batch.corp.example.test",
        }
    ]
    memberships = [
        _membership("APP_READ", "2201", "alice", "1101", "user"),
        _membership("APP_READ", "2201", "carol", "1103", "user"),
        _membership("APP_READ", "2201", "dave", "1104", "user"),
        _membership("APP_AUDIT", "2203", "francois", "1106", "user"),
    ]
    if variant in {"modified", "unknown"}:
        memberships = [row for row in memberships if row["Member"] != "carol"]
        memberships = [(_membership("APP_READ", "2201", "david.renamed", "1104", "user") if row["MemberSID"].endswith("-1104") else row) for row in memberships]
        memberships.append(_membership("APP_ADMIN", "2202", "bob", "1102", "user"))
        memberships.append(_membership("APP_ADMIN", "2202", "svc-batch$", "3101", "msDS-ManagedServiceAccount", dn="CN=svc-batch,CN=Managed Service Accounts,DC=corp,DC=example,DC=test"))
    completeness = "unknown" if variant == "unknown" else "full"
    errors = "ObjectType,ObjectIdentifier,ObjectSID,Operation,ErrorCode,ErrorMessage\n"
    if variant == "unknown":
        errors += "group,APP_AUDIT,S-1-5-21-100-200-300-2203,Get-ADGroupMember,timeout,simulated timeout\n"
    with ZipFile(archive, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.yaml", f"schema_version: 1\nsource_type: active_directory\nprovider: corp-ad\ndomain: corp.example.test\ndomain_sid: S-1-5-21-100-200-300\ncompleteness: {completeness}\nstatistics:\n  users: {len(users)}\n  groups: {len(groups)}\n  service_accounts: {len(service_accounts)}\n  computers: 0\n  memberships: {len(memberships)}\n  collection_errors: {1 if variant == 'unknown' else 0}\n")
        zf.writestr("users.csv", _csv(list(users[0]), users))
        zf.writestr("groups.csv", _csv(list(groups[0]), groups))
        zf.writestr("service_accounts.csv", _csv(list(service_accounts[0]), service_accounts))
        zf.writestr("computers.csv", _csv(["SamAccountName", "Name", "SID", "DistinguishedName", "Enabled", "DNSHostName", "Description", "ObjectGUID", "PrimaryGroupID"], []))
        zf.writestr("memberships.csv", _csv(list(memberships[0]), memberships))
        zf.writestr("collection-errors.csv", errors)
    return archive


def _user(sam: str, sid: str, display: str, enabled: str) -> dict[str, str]:
    return {
        "SamAccountName": sam,
        "UserPrincipalName": f"{sam}@corp.example.test",
        "DisplayName": display,
        "Mail": f"{sam}@corp.example.test",
        "Enabled": enabled,
        "SID": sid,
        "DistinguishedName": f"CN={display},OU=Users,DC=corp,DC=example,DC=test",
        "Description": "Lifecycle test user",
        "PrimaryGroupID": "513",
        "LockedOut": "false",
        "ObjectGUID": "00000000-0000-0000-0000-" + sid.rsplit("-", 1)[-1].zfill(12),
        "LastLogonDate": "",
        "PasswordLastSet": "",
        "AccountExpirationDate": "",
        "WhenCreated": "",
        "ServicePrincipalName": "",
    }


def _group(sam: str, rid_sid: str, description: str) -> dict[str, str]:
    return {
        "SamAccountName": sam,
        "Name": sam,
        "SID": rid_sid,
        "DistinguishedName": f"CN={sam},OU=Groups,DC=corp,DC=example,DC=test",
        "Description": description,
        "GroupScope": "Global",
        "GroupCategory": "Security",
    }


def _membership(group: str, group_rid: str, member: str, member_rid: str, member_type: str, dn: str | None = None) -> dict[str, str]:
    return {
        "Group": group,
        "GroupSID": f"S-1-5-21-100-200-300-{group_rid}",
        "Member": member,
        "MemberSID": f"S-1-5-21-100-200-300-{member_rid}",
        "MemberType": member_type,
        "MemberDN": dn or f"CN={member},OU=Users,DC=corp,DC=example,DC=test",
        "MembershipType": "direct",
    }


def _csv(fieldnames: list[str], rows: list[dict[str, str]]) -> str:
    stream = StringIO()
    writer = csv.DictWriter(stream, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()
