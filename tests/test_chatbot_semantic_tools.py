from __future__ import annotations

from access_review_engine.chatbot.config import ChatbotConfig
from access_review_engine.chatbot.context import AuthorizationContext, UIHints
from access_review_engine.chatbot.security.tool_policy import validate_tool_arguments
from access_review_engine.chatbot.service import AssistantService, FakeLLMProvider
from access_review_engine.chatbot.tools.semantic import (
    SEMANTIC_TOOL_SCHEMAS,
    aggregate_authorized_data,
    get_authentication_posture_summary,
    get_authorized_access,
    get_authorized_identity,
    search_authorized_accesses,
    search_authorized_campaigns,
    search_authorized_identities,
    search_authorized_remediations,
    search_authorized_reviews,
)
from access_review_engine.chatbot.tools.ui import get_ui_help
from access_review_engine.storage import Repository


def _context(role: str, *scopes: str, username: str = "alice") -> AuthorizationContext:
    return AuthorizationContext("subject", username, role, frozenset(scopes))


def _seed(repo: Repository) -> None:
    for provider in ("A", "B"):
        repo.upsert("providers", {"id": provider, "name": provider})
    repo.upsert(
        "accesses",
        {
            "id": "access-a",
            "provider": "A",
            "name": "finance-admin",
            "display_name": "Finance administrators",
            "permission": {"identifier": "invoice.write"},
            "metadata": {"privileged": True},
            "access_owner": {"provider": "A", "identity": "owner-a"},
        },
    )
    repo.upsert(
        "accesses",
        {
            "id": "access-b",
            "provider": "B",
            "name": "secret-admin",
            "display_name": "Secret administrators",
            "permission": {"identifier": "secret.write"},
            "metadata": {"privileged": True},
        },
    )
    repo.upsert(
        "identities",
        {
            "id": "identity-a",
            "provider": "A",
            "identifier": "svc-finance",
            "type": "technical_account",
            "status": "active",
        },
    )
    repo.upsert(
        "identities",
        {
            "id": "identity-b",
            "provider": "B",
            "identifier": "svc-secret",
            "type": "technical_account",
            "status": "active",
        },
    )
    repo.upsert(
        "access_assignments",
        {
            "id": "assignment-a",
            "provider": "A",
            "access_name": "finance-admin",
            "identity_provider": "A",
            "identity_identifier": "svc-finance",
        },
    )
    repo.upsert(
        "access_assignments",
        {
            "id": "assignment-b",
            "provider": "B",
            "access_name": "secret-admin",
            "identity_provider": "B",
            "identity_identifier": "svc-secret",
        },
    )
    repo.upsert(
        "snapshots",
        {
            "id": "snapshot-a",
            "created_at": "2026-01-01T00:00:00Z",
            "providers": [{"name": "A"}],
            "authentication_posture": {
                "provider": "A",
                "completeness": "full",
                "controls": {"mfa": {"status": "collected", "value": "required"}},
            },
        },
    )
    repo.upsert(
        "campaigns",
        {
            "id": "campaign-a",
            "name": "Finance review",
            "status": "open",
            "scope": {"type": "providers", "values": ["A"]},
        },
    )
    repo.upsert(
        "campaigns",
        {
            "id": "campaign-b",
            "name": "Secret review",
            "status": "open",
            "scope": {"type": "providers", "values": ["B"]},
        },
    )
    repo.upsert(
        "review_items",
        {
            "id": "review-a",
            "campaign_id": "campaign-a",
            "identity_provider": "A",
            "identity_identifier": "svc-finance",
            "access_provider": "A",
            "access_name": "finance-admin",
            "classification": "unexpected",
            "reviewer": {"identity": "alice"},
        },
    )
    repo.upsert(
        "review_items",
        {
            "id": "review-b",
            "campaign_id": "campaign-b",
            "identity_provider": "B",
            "identity_identifier": "svc-secret",
            "access_provider": "B",
            "access_name": "secret-admin",
            "classification": "unexpected",
            "reviewer": {"identity": "bob"},
        },
    )
    repo.upsert(
        "remediation_actions",
        {"id": "action-a", "review_item_id": "review-a", "action": "revoke"},
    )
    repo.upsert(
        "remediation_actions",
        {"id": "action-b", "review_item_id": "review-b", "action": "revoke"},
    )
    repo.upsert(
        "information_systems",
        {"id": "finance", "name": "Finance", "active": True},
    )
    repo.upsert(
        "scope_assignments",
        {
            "id": "scope-access-a",
            "scope_type": "information_system",
            "scope_id": "finance",
            "object_type": "access",
            "object_id": "access-a",
        },
    )


def test_access_identity_and_aggregate_never_leak_other_provider(tmp_path) -> None:
    with Repository(tmp_path / "semantic.db") as repo:
        _seed(repo)
        context = _context("OPERATOR", "A")
        accesses = search_authorized_accesses(repo, {"limit": 25}, context, UIHints())
        identities = search_authorized_identities(repo, {"limit": 25}, context, UIHints())
        aggregate = aggregate_authorized_data(
            repo,
            {"entity": "access", "metric": "count", "group_by": "provider"},
            context,
            UIHints(),
        )
        hidden_access = get_authorized_access(repo, {"access_id": "access-b"}, context, UIHints())
        hidden_identity = get_authorized_identity(
            repo, {"identity_id": "identity-b"}, context, UIHints()
        )
    assert [item["id"] for item in accesses["items"]] == ["access-a"]
    assert [item["id"] for item in identities["items"]] == ["identity-a"]
    assert identities["items"][0]["privileged_access"] is True
    assert aggregate["groups"] == {"A": 1}
    assert hidden_access == {"available": False, "item": None}
    assert hidden_identity == {"available": False, "item": None}
    assert (
        "secret"
        not in str((accesses, identities, aggregate, hidden_access, hidden_identity)).casefold()
    )


def test_perimeter_filter_is_classification_not_new_authorization(tmp_path) -> None:
    with Repository(tmp_path / "semantic.db") as repo:
        _seed(repo)
        context = _context("OPERATOR", "A")
        included = search_authorized_accesses(
            repo,
            {"information_system_ids": ["finance"], "limit": 25},
            context,
            UIHints(),
        )
        excluded = search_authorized_accesses(
            repo,
            {"information_system_ids": ["other"], "limit": 25},
            context,
            UIHints(),
        )
    assert included["count"] == 1
    assert excluded["count"] == 0


def test_ui_help_returns_only_real_role_authorized_routes(tmp_path) -> None:
    with Repository(tmp_path / "ui.db") as repo:
        operator = get_ui_help(repo, {"topic": "SI"}, _context("OPERATOR", "A"), UIHints())
        denied = get_ui_help(repo, {"page": "USERS"}, _context("OPERATOR", "A"), UIHints())
        admin = get_ui_help(repo, {"page": "USERS"}, _context("ADMIN"), UIHints())
    assert operator["item"]["route"] == "/perimeters"
    assert operator["item"]["navigation_path"] == "Access & Reference → Scopes"
    assert denied == {"available": False, "item": None}
    assert admin["item"]["route"] == "/system/users"


def test_finance_report_uses_deterministic_authorized_sections_and_sources(tmp_path) -> None:
    with Repository(tmp_path / "report.db") as repo:
        _seed(repo)
        repo.upsert(
            "accesses",
            {
                "id": "access-a-2",
                "provider": "A",
                "name": "finance-reader",
                "permission": {"identifier": "invoice.read"},
            },
        )
        repo.upsert(
            "scope_assignments",
            {
                "id": "scope-access-a-2",
                "scope_type": "information_system",
                "scope_id": "finance",
                "object_type": "access",
                "object_id": "access-a-2",
            },
        )
        service = AssistantService(
            lambda: Repository(tmp_path / "report.db"),
            ChatbotConfig(enabled=True, provider="fake", model="test"),
            FakeLLMProvider(),
        )
        brief = service.build_brief(
            repo,
            _context("OPERATOR", "A"),
            UIHints(),
            "Fais-moi un rapport sur le contrôle d'accès du SI Finance.",
        )
        markdown = service.render_brief_markdown(brief)
    assert brief.scope == "Information System: Finance"
    assert brief.sections["accesses"] == {
        "count": 2,
        "privileged": 1,
        "without_owner": 1,
        "by_completeness": {"not_defined": 2},
    }
    assert brief.sections["reviews"]["by_classification"] == {"unexpected": 1}
    assert brief.sources
    assert "Sources et références" in markdown
    assert "secret-admin" not in markdown.casefold()
    assert "provider b" not in markdown.casefold()


def test_role_visibility_contract_for_reviews_campaigns_and_remediations(tmp_path) -> None:
    with Repository(tmp_path / "semantic.db") as repo:
        _seed(repo)
        group_owner = _context("GROUP_OWNER", username="alice")
        assert search_authorized_reviews(repo, {"limit": 25}, group_owner, UIHints())["count"] == 1
        assert (
            search_authorized_campaigns(repo, {"limit": 25}, group_owner, UIHints())["count"] == 1
        )
        business = _context("BUSINESS_ADMIN", "A")
        assert search_authorized_campaigns(repo, {"limit": 25}, business, UIHints())["count"] == 0
        assert search_authorized_accesses(repo, {"limit": 25}, business, UIHints())["count"] == 0
        remediations = search_authorized_remediations(
            repo, {"limit": 25}, _context("REMEDIATION_MANAGER", "A"), UIHints()
        )
    assert remediations["count"] == 1
    assert remediations["items"][0]["id"] == "action-a"


def test_authentication_posture_preserves_not_collected_semantics(tmp_path) -> None:
    with Repository(tmp_path / "semantic.db") as repo:
        _seed(repo)
        result = get_authentication_posture_summary(repo, {}, _context("ADMIN", "*"), UIHints())
    by_provider = {item["provider"]: item for item in result["providers"]}
    assert by_provider["A"]["state"] == "collected"
    assert by_provider["B"]["state"] == "not_collected"
    assert result["note"] == (
        "not_collected does not mean that an authentication control is disabled"
    )


def test_semantic_search_is_bounded_but_count_is_exact(tmp_path) -> None:
    with Repository(tmp_path / "semantic.db") as repo:
        for index in range(30):
            repo.upsert(
                "accesses",
                {"id": f"access-{index}", "provider": "A", "name": f"access-{index}"},
            )
        result = search_authorized_accesses(
            repo, {"limit": 5}, _context("OPERATOR", "A"), UIHints()
        )
    assert result["count"] == 30
    assert len(result["items"]) == 5
    assert result["truncated"] is True


def test_tool_schema_validator_supports_nested_controlled_types() -> None:
    schema = next(
        item for item in SEMANTIC_TOOL_SCHEMAS if item["name"] == "aggregate_authorized_data"
    )
    assert validate_tool_arguments(
        {
            "entity": "access",
            "metric": "count",
            "group_by": "provider",
            "filters": {"provider": "A", "capability": None},
        },
        schema,
    )
    assert not validate_tool_arguments({"entity": "access", "metric": "sum", "filters": {}}, schema)
    assert not validate_tool_arguments(
        {"entity": "access", "metric": "count", "filters": {"sql": "SELECT *"}},
        schema,
    )


def test_access_schema_validates_arrays_booleans_and_limits() -> None:
    schema = next(
        item for item in SEMANTIC_TOOL_SCHEMAS if item["name"] == "search_authorized_accesses"
    )
    assert validate_tool_arguments(
        {"organization_ids": ["org-1"], "privileged": True, "limit": 10}, schema
    )
    assert not validate_tool_arguments({"organization_ids": [1]}, schema)
    assert not validate_tool_arguments({"limit": 10_000}, schema)
