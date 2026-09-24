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
