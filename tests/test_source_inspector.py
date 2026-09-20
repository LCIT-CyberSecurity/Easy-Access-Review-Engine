from __future__ import annotations

import json
import subprocess

from access_review_engine.source_inspector import (
    discover_source_attributes,
    get_source_object,
    search_source_objects,
)


def _ad() -> dict[str, object]:
    return {
        "provider": "ad-corp",
        "type": "active_directory",
        "connection": {"server": "dc.example.test"},
        "collection": {"timeout": 5},
        "business_mapping": {
            "application": {"mode": "attribute", "attribute": "extensionAttribute5"},
        },
    }


def _ldap() -> dict[str, object]:
    return {
        "provider": "ldap-production",
        "type": "openldap",
        "connection": {"uri": "ldaps://ldap.example.test", "base_dn": "dc=example,dc=test"},
        "collection": {"command_timeout": 5},
    }


def test_ad_search_and_details_are_bounded_and_redacted() -> None:
    rows = [
        {
            "identifier": f"SID-{index}",
            "display_name": f"Group {index}",
            "attributes": {
                "Description": ["Finance"],
                "extensionAttribute5": ["Sage"],
                "unicodePwd": ["must-never-leak"],
                "apiToken": ["must-never-leak"],
            },
        }
        for index in range(4)
    ]
    commands: list[list[str]] = []

    def runner(command: list[str], _env: dict[str, str], _timeout: int) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, json.dumps(rows), "")

    page = search_source_objects(_ad(), "group", "Finance; Remove-Item C:\\", 2, 1, runner)
    detail = get_source_object(_ad(), "group", "SID-1", runner)

    assert [row["identifier"] for row in page["items"]] == ["SID-1", "SID-2"]
    assert page["has_more"] is True
    assert "unicodePwd" not in detail["attributes"]
    assert "apiToken" not in detail["attributes"]
    assert all(command[0] == "pwsh" for command in commands)
    assert not any("must-never-leak" in argument for command in commands for argument in command)
    assert "Finance; Remove-Item C:\\" in commands[0]


def test_openldap_search_escapes_filter_input_and_never_places_credentials_in_command() -> None:
    seen: list[list[str]] = []

    def runner(command: list[str], _env: dict[str, str], _timeout: int) -> subprocess.CompletedProcess[str]:
        seen.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            "dn: cn=Finance,dc=example,dc=test\nentryUUID: uuid-1\ncn: Finance\ndescription: Team\n\n",
            "",
        )

    result = search_source_objects(_ldap(), "group", "*)(userPassword=*)", 25, 0, runner)
    assert result["items"][0]["display_name"] == "Finance"
    ldap_filter = next(argument for argument in seen[0] if argument.startswith("(&"))
    assert "\\2a\\29\\28userPassword=\\2a\\29" in ldap_filter
    assert "-w" not in seen[0]
    assert "must-never-leak" not in seen[0]


def test_attribute_discovery_reports_bounded_coverage_and_safe_samples() -> None:
    rows = [
        {"identifier": "1", "attributes": {"extensionAttribute5": ["Sage"], "description": ["A"]}},
        {"identifier": "2", "attributes": {"description": ["B"]}},
    ]

    def runner(command: list[str], _env: dict[str, str], _timeout: int) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, json.dumps(rows), "")

    attributes = discover_source_attributes(_ad(), "group", runner)
    assert attributes["extensionAttribute5"]["coverage"] == 50
    assert attributes["extensionAttribute5"]["samples"] == ["Sage"]
    assert attributes["description"]["coverage"] == 100
