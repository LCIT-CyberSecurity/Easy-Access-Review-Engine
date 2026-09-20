from __future__ import annotations

import pytest

from access_review_engine.application import _enrich_access
from access_review_engine.connector_capabilities import connector_capabilities
from access_review_engine.domain import Access, ControlObject, Permission
from access_review_engine.source_mapping import (
    BUSINESS_CONTEXT_METADATA_KEY,
    SourceMappingError,
    build_business_context,
    mapping_diagnostics,
    map_access_business_context,
    required_mapping_attributes,
    validate_business_mapping,
)


def _group(provider: str = "corp-ad") -> Access:
    return Access(
        "GG_SAGE_COMPTA_RW:member",
        provider,
        ControlObject("group", "GG_SAGE_COMPTA_RW", native_id="S-1-GROUP"),
        Permission("member"),
    )


def test_ad_mapping_adds_context_without_changing_technical_access() -> None:
    access = _group()
    original_key = access.key()
    config = {
        "business_mapping": {
            "description": {"mode": "attribute", "attribute": "info"},
            "application": {"mode": "attribute", "attribute": "extensionAttribute5"},
            "business_permission": {"mode": "attribute", "attribute": "extensionAttribute6"},
            "resource": {"mode": "attribute", "attribute": "extensionAttribute7"},
        }
    }

    map_access_business_context(
        access,
        "active_directory",
        {
            "info": "Finance access",
            "extensionAttribute5": "Sage",
            "extensionAttribute6": "ReadWrite",
            "extensionAttribute7": "Invoices",
        },
        config,
    )

    context = access.metadata[BUSINESS_CONTEXT_METADATA_KEY]
    assert access.key() == original_key
    assert access.permission.identifier == "member"
    assert context["application"] == {
        "value": "Sage",
        "provenance": "source_attribute",
        "mapping_mode": "configured",
        "attribute": "extensionAttribute5",
    }
    assert context["business_permission"]["value"] == "ReadWrite"
    assert context["resource"]["value"] == "Invoices"


def test_openldap_default_and_custom_mapping_keep_member_semantics() -> None:
    access = _group("ldap-production")
    map_access_business_context(
        access,
        "openldap",
        {"cn": "finance", "description": "Finance team", "businessApp": "Sage"},
        {"business_mapping": {"application": {"mode": "attribute", "attribute": "businessApp"}}},
    )
    context = access.metadata[BUSINESS_CONTEXT_METADATA_KEY]
    assert access.permission.identifier == "member"
    assert access.name == "GG_SAGE_COMPTA_RW:member"
    assert context["description"] == {
        "value": "Finance team",
        "provenance": "source_attribute",
        "mapping_mode": "default",
        "attribute": "description",
    }
    assert context["application"]["value"] == "Sage"


def test_new_observation_replaces_removed_source_context() -> None:
    access = _group()
    config = {"business_mapping": {"business_permission": {"mode": "attribute", "attribute": "extensionAttribute6"}}}
    map_access_business_context(access, "active_directory", {"extensionAttribute6": "ReadWrite"}, config)
    assert access.metadata[BUSINESS_CONTEXT_METADATA_KEY]["business_permission"]["value"] == "ReadWrite"

    map_access_business_context(access, "active_directory", {}, config)
    assert "business_permission" not in access.metadata[BUSINESS_CONTEXT_METADATA_KEY]


def test_reobserved_directory_access_clears_removed_mapped_description() -> None:
    existing = _group()
    mapped = {"business_mapping": {"description": {"mode": "attribute", "attribute": "info"}}}
    map_access_business_context(existing, "active_directory", {"info": "Finance"}, mapped)
    incoming = _group()
    map_access_business_context(incoming, "active_directory", {}, mapped)

    _enrich_access(existing, incoming)

    assert existing.description is None
    assert "description" not in existing.metadata[BUSINESS_CONTEXT_METADATA_KEY]


def test_mapping_is_source_local_and_supports_static_and_none() -> None:
    source_a = {"business_mapping": {"application": {"mode": "static", "value": "Sage"}}}
    source_b = {"business_mapping": {"application": {"mode": "none"}}}
    a, b = _group("ad-a"), _group("ad-b")
    map_access_business_context(a, "active_directory", {}, source_a)
    map_access_business_context(b, "active_directory", {}, source_b)
    assert a.metadata[BUSINESS_CONTEXT_METADATA_KEY]["application"]["value"] == "Sage"
    assert "application" not in b.metadata[BUSINESS_CONTEXT_METADATA_KEY]


def test_only_configured_safe_fields_are_required() -> None:
    config = {
        "business_mapping": {
            "application": {"mode": "attribute", "attribute": "extensionAttribute5"},
            "resource": {"mode": "attribute", "attribute": "extensionAttribute7"},
        }
    }
    assert required_mapping_attributes(config, "active_directory") == (
        "extensionAttribute5",
        "extensionAttribute7",
    )


def test_sensitive_technical_and_executable_attribute_names_are_rejected() -> None:
    for attribute in (
        "unicodePwd",
        "supplementalCredentials",
        "objectGUID",
        "member",
        "sAMAccountName",
        "uid",
        "customPasswordField",
        "x); Write-Host pwned",
    ):
        with pytest.raises(SourceMappingError):
            validate_business_mapping(
                "active_directory",
                {"application": {"mode": "attribute", "attribute": attribute}},
            )


def test_connector_capabilities_are_explicit_and_mapping_provenance_is_factual() -> None:
    expected = {
        "attribute_mapping": True,
        "safe_attribute_sampling": True,
        "source_browser": True,
        "native_permissions": False,
        "native_targets": False,
    }
    assert connector_capabilities("active_directory").__dict__ == expected
    assert connector_capabilities("openldap").__dict__ == expected
    assert connector_capabilities("future_iam").source_browser is False
    with pytest.raises(SourceMappingError):
        validate_business_mapping("future_iam", None)

    default = build_business_context("active_directory", {"Description": "Finance"})["description"]
    configured = build_business_context(
        "active_directory",
        {"extensionAttribute6": "ReadWrite"},
        {"business_mapping": {"business_permission": {"mode": "attribute", "attribute": "extensionAttribute6"}}},
    )["business_permission"]
    static = build_business_context(
        "active_directory",
        {},
        {"business_mapping": {"application": {"mode": "static", "value": "Sage"}}},
    )["application"]
    assert default == {"value": "Finance", "provenance": "source_attribute", "mapping_mode": "default", "attribute": "Description"}
    assert configured == {"value": "ReadWrite", "provenance": "source_attribute", "mapping_mode": "configured", "attribute": "extensionAttribute6"}
    assert static == {"value": "Sage", "provenance": "static"}

    rows = mapping_diagnostics(
        "active_directory",
        {"business_mapping": {"business_permission": {"mode": "attribute", "attribute": "extensionAttribute6"}}},
        {"extensionAttribute6": {"coverage": 50, "samples": ["ReadWrite"]}},
    )
    diagnostic = next(row for row in rows if row["field"] == "business_permission")
    assert diagnostic["mapping_mode"] == "configured"
    assert diagnostic["coverage"] == 50


def test_default_diagnostics_choose_first_populated_candidate_without_reordering() -> None:
    rows = mapping_diagnostics(
        "active_directory",
        None,
        {
            "Name": {"coverage": 0, "samples": []},
            "SamAccountName": {"coverage": 100, "samples": ["alice"]},
        },
    )
    display_name = next(row for row in rows if row["field"] == "display_name")
    assert display_name["attribute"] == "SamAccountName"
    assert display_name["coverage"] == 100

    preferred = mapping_diagnostics(
        "active_directory",
        None,
        {"Name": {"coverage": 90}, "SamAccountName": {"coverage": 100}},
    )
    assert next(row for row in preferred if row["field"] == "display_name")["attribute"] == "Name"

    empty = mapping_diagnostics(
        "active_directory",
        None,
        {"Name": {"coverage": 0}, "SamAccountName": {"coverage": 0}},
    )
    empty_display = next(row for row in empty if row["field"] == "display_name")
    assert empty_display["attribute"] == "Name"
    assert empty_display["coverage"] == 0


def test_explicit_attribute_diagnostics_never_fall_back_to_default() -> None:
    rows = mapping_diagnostics(
        "active_directory",
        {"business_mapping": {"display_name": {"mode": "attribute", "attribute": "extensionAttribute6"}}},
        {"Name": {"coverage": 100}, "extensionAttribute6": {"coverage": 0}},
    )
    display_name = next(row for row in rows if row["field"] == "display_name")
    assert display_name["attribute"] == "extensionAttribute6"
    assert display_name["coverage"] == 0
    assert display_name["status"] == "warning"
