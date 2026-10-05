from __future__ import annotations

import sqlite3

import pytest
from access_review_engine.chatbot.config import ChatbotConfig
from access_review_engine.chatbot.guardrails import (
    GuardrailPolicy,
    apply_policy,
    load_policy,
    save_policy,
    validate_policy,
)
from access_review_engine.system_admin import init_system


def test_guardrail_defaults_lock_fundamental_controls_and_apply_bounds() -> None:
    policy = GuardrailPolicy.defaults()
    payload = policy.as_dict()
    assert payload["locked_security"]["read_only"] is True
    assert payload["locked_security"]["no_arbitrary_sql"] is True
    assert payload["locked_security"]["authorization_enforcement"] is True
    effective = apply_policy(ChatbotConfig(max_tool_calls=20), policy)
    assert effective.max_tool_calls == 6
    assert effective.max_tool_rounds == 3
    assert effective.max_result_items == 100


def test_fundamental_controls_cannot_be_disabled() -> None:
    payload = GuardrailPolicy.defaults().as_dict()
    payload["locked_security"]["read_only"] = False
    with pytest.raises(ValueError, match="cannot be changed"):
        validate_policy(payload)


def test_guardrail_policy_round_trip_uses_existing_system_settings(tmp_path) -> None:
    conn = sqlite3.connect(tmp_path / "settings.db")
    conn.row_factory = sqlite3.Row
    init_system(conn)
    payload = GuardrailPolicy.defaults().as_dict()
    payload["domains"]["authentication"] = False
    payload["knowledge_sources"] = {"mode": "selected", "publishers": ["CNIL", "CISA"]}
    payload["limits"]["max_results"] = 25
    policy = validate_policy(payload)
    save_policy(conn, policy)
    loaded = load_policy(conn)
    conn.close()
    assert loaded.domains["authentication"] is False
    assert loaded.enabled_publishers == ("CNIL", "CISA")
    assert loaded.max_results == 25


def test_disabled_domain_is_rejected_before_provider_use() -> None:
    payload = GuardrailPolicy.defaults().as_dict()
    payload["domains"]["authentication"] = False
    policy = validate_policy(payload)
    assert policy.allows("EARE_ACCESS_GUIDANCE", "Quelle durée de session admin ?") == (
        False,
        "domain_disabled:authentication",
    )


def test_external_guidance_domain_is_not_publisher_specific() -> None:
    payload = GuardrailPolicy.defaults().as_dict()
    payload["domains"]["external_guidance"] = False
    policy = validate_policy(payload)
    assert policy.allows("EARE_ACCESS_GUIDANCE", "Que recommande CISA sur IAM ?") == (
        True,
        "allowed",
    )


def test_max_results_is_capped_at_one_hundred() -> None:
    payload = GuardrailPolicy.defaults().as_dict()
    payload["limits"]["max_results"] = 101
    with pytest.raises(ValueError, match="between 1 and 100"):
        validate_policy(payload)
