from access_review_engine.guidance import GuidanceContext, build_guidance


def _context(role: str, **values: object) -> GuidanceContext:
    return GuidanceContext(
        role=role,
        route=str(values.pop("route", "/")),
        allowed_routes=frozenset(values.pop("allowed_routes", {"/campaigns/new", "/system/users", "/reviews", "/actions", "/sources", "/golden"})),
        **values,
    )


def test_admin_hands_off_to_operator_instead_of_making_campaign_primary() -> None:
    result = build_guidance(_context("ADMIN", source_count=2, synchronized_source_count=2, latest_snapshot=True, golden_available=True, operator_count=1))
    assert result["recommendations"][0]["id"] == "handoff_to_operator"
    assert result["recommendations"][0]["priority"] == "primary"
    assert result["recommendations"][1]["id"] == "admin_prepare_campaign"
    assert result["recommendations"][1]["priority"] == "secondary"


def test_admin_without_operator_is_told_to_create_one() -> None:
    result = build_guidance(_context("ADMIN", source_count=1, latest_snapshot=True, golden_available=True, operator_count=0))
    assert result["recommendations"][0]["id"] == "create_operator"
    assert result["recommendations"][0]["action_url"] == "/system/users"


def test_operator_gets_governance_journey() -> None:
    result = build_guidance(_context("OPERATOR", source_count=1, latest_snapshot=True, golden_available=True))
    assert result["recommendations"][0]["id"] == "prepare_campaign"
    assert result["recommendations"][0]["action_url"] == "/campaigns/new"


def test_group_owner_only_gets_assigned_review_guidance() -> None:
    result = build_guidance(_context("GROUP_OWNER", assigned_pending_reviews=4, source_count=10, latest_snapshot=True, golden_available=True))
    assert [item["id"] for item in result["recommendations"]] == ["complete_assigned_reviews"]
    assert result["recommendations"][0]["action_url"] == "/reviews"


def test_remediation_roles_only_get_remediation_guidance() -> None:
    result = build_guidance(_context("REMEDIATION_MANAGER", pending_actions=3, source_count=4, latest_snapshot=True, golden_available=True))
    assert [item["id"] for item in result["recommendations"]] == ["process_remediation"]
    assert result["recommendations"][0]["action_url"] == "/actions"


def test_operator_campaign_recommendation_is_blocked_when_campaign_deep_link_is_not_authorized() -> None:
    result = build_guidance(_context(
        "OPERATOR",
        source_count=1,
        latest_snapshot=True,
        golden_available=True,
        pending_reviews=2,
        open_campaigns=({"id": "campaign-us", "name": "US", "pending": 2, "unresolved_reviewers": 0},),
        allowed_routes={"/campaigns", "/campaigns/new"},
    ))
    assert result["recommendations"][0]["id"] == "campaign_scope_blocked"
    assert result["recommendations"][0]["action_url"] is None


def test_guidance_is_read_only_and_route_help_is_deterministic() -> None:
    result = build_guidance(_context("OPERATOR", route="/golden", source_count=1))
    assert result["read_only"] is True
    assert result["page_help"]["title"] == "guide.page.golden.title"


def test_exported_and_not_completed_remediation_remain_open() -> None:
    result = build_guidance(_context(
        "REMEDIATION_MANAGER",
        pending_actions=1,
        open_actions=3,
        exported_actions=1,
        not_completed_actions=1,
        completed_actions=4,
    ))
    assert result["state"]["open_actions"] == 3
    assert result["state"]["exported_actions"] == 1
    assert result["recommendations"][0]["id"] == "process_remediation"


def test_admin_handoff_requires_operator_domain_coverage() -> None:
    result = build_guidance(_context(
        "ADMIN",
        source_count=2,
        latest_snapshot=True,
        golden_available=True,
        operator_count=1,
        operator_coverage_complete=False,
        uncovered_operator_domains=("AWS-PROD",),
    ))
    assert result["recommendations"][0]["id"] == "complete_operator_coverage"


def test_operator_campaign_priority_is_deterministic() -> None:
    result = build_guidance(_context(
        "OPERATOR",
        username="alice",
        source_count=1,
        latest_snapshot=True,
        golden_available=True,
        pending_reviews=2,
        open_campaigns=(
            {"id": "new", "pilot": "bob", "due_at": "2026-10-01", "opened_at": "2026-09-24", "pending": 1},
            {"id": "mine", "pilot": "alice", "due_at": "2026-12-01", "opened_at": "2026-09-01", "pending": 1},
        ),
        allowed_routes={"/campaigns/new", "/campaigns/mine"},
    ))
    assert result["recommendations"][0]["action_url"] == "/campaigns/mine"


def test_business_admin_can_review_but_not_update_remediation() -> None:
    result = build_guidance(_context("BUSINESS_ADMIN", open_actions=4, pending_actions=2))
    assert result["recommendations"][0]["id"] == "review_remediation"
    assert result["recommendations"][0]["title"] == "guide.reviewRemediation.title"


def test_group_owner_state_uses_assigned_work_only() -> None:
    result = build_guidance(_context(
        "GROUP_OWNER",
        pending_reviews=0,
        assigned_pending_reviews=6,
        assigned_campaign_count=2,
        source_count=12,
        latest_snapshot=True,
        golden_available=True,
    ))
    assert result["state"]["assigned_pending_reviews"] == 6
    assert result["state"]["assigned_campaign_count"] == 2
    assert "sources" not in result["state"] or result["state"]["sources"] == 12


def test_guidance_exposes_campaign_priority_facts_and_readiness() -> None:
    result = build_guidance(_context(
        "OPERATOR",
        source_count=1,
        latest_snapshot=True,
        golden_available=True,
        username="alice",
        open_campaigns=({"id": "c1", "pilot": "alice", "due_at": "2026-09-01", "opened_at": "2026-08-01", "pending": 2, "overdue": True},),
        campaign_readiness={"campaign_id": "draft-1", "ready": False, "blockers": ["unresolved_reviewers"]},
    ))
    assert result["campaign_readiness"]["blockers"] == ["unresolved_reviewers"]
    assert result["state"]["configured_source_count"] == 1


def test_admin_is_asked_for_a_dedicated_read_only_account_per_source() -> None:
    result = build_guidance(_context("ADMIN", source_count=2, latest_snapshot=True, golden_available=True, operator_count=1, sources_without_read_only_account=("corp-ad",)))
    advice = next(item for item in result["recommendations"] if item["id"] == "dedicated_read_only_accounts")
    assert advice["action_url"] == "/sources"
    assert advice["priority"] == "attention"
    assert result["state"]["sources_without_read_only_account"] == ["corp-ad"]


def test_read_only_advice_disappears_once_every_source_is_confirmed() -> None:
    result = build_guidance(_context("ADMIN", source_count=2, latest_snapshot=True, golden_available=True, operator_count=1))
    assert all(item["id"] != "dedicated_read_only_accounts" for item in result["recommendations"])


def test_only_admins_are_asked_about_collection_accounts() -> None:
    result = build_guidance(_context("OPERATOR", source_count=1, latest_snapshot=True, golden_available=True, sources_without_read_only_account=("corp-ad",)))
    assert all(item["id"] != "dedicated_read_only_accounts" for item in result["recommendations"])
