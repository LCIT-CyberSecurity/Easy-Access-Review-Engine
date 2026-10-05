from __future__ import annotations

import json
from dataclasses import dataclass, replace
from typing import Any

from access_review_engine.chatbot.config import ChatbotConfig

LOCKED_CONTROLS = {
    "read_only": True,
    "server_side_identity": True,
    "authorization_enforcement": True,
    "scope_filtering": True,
    "secret_filtering": True,
    "prompt_injection_protection": True,
    "tool_allowlist": True,
    "no_arbitrary_sql": True,
    "no_arbitrary_url": True,
    "bounded_tool_outputs": True,
}

DEFAULT_DOMAINS = {
    "eare_product_help": True,
    "access_control": True,
    "identity_governance": True,
    "authentication": True,
    "privileged_access": True,
    "external_guidance": True,
}


@dataclass(frozen=True)
class GuardrailPolicy:
    domains: dict[str, bool]
    source_mode: str = "all_verified"
    enabled_publishers: tuple[str, ...] = ()
    max_tool_calls: int = 6
    max_tool_rounds: int = 3
    max_results: int = 100
    history_messages: int = 12
    retention_days: int = 30
    conversation_logging: bool = True
    tool_logging: bool = True

    @classmethod
    def defaults(cls) -> GuardrailPolicy:
        return cls(dict(DEFAULT_DOMAINS))

    def as_dict(self) -> dict[str, Any]:
        return {
            "locked_security": dict(LOCKED_CONTROLS),
            "domains": dict(self.domains),
            "knowledge_sources": {
                "mode": self.source_mode,
                "publishers": list(self.enabled_publishers),
            },
            "limits": {
                "max_tool_calls": self.max_tool_calls,
                "max_tool_rounds": self.max_tool_rounds,
                "max_results": self.max_results,
                "history_messages": self.history_messages,
                "retention_days": self.retention_days,
            },
            "logging": {
                "conversations": self.conversation_logging,
                "tool_calls": self.tool_logging,
            },
        }

    def allows(self, intent: str, question: str) -> tuple[bool, str]:
        text = question.casefold()
        if intent in {
            "EARE_USAGE",
            "EARE_NAVIGATION",
            "EARE_DASHBOARD",
            "EARE_CAMPAIGN",
            "EARE_GOLDEN",
            "EARE_REVIEW",
            "EARE_SOURCE",
            "EARE_REPORT",
        }:
            key = "eare_product_help"
        elif any(
            term in text
            for term in (
                "mfa",
                "authent",
                "session",
                "password",
                "mot de passe",
                "sso",
                "token",
                "federat",
            )
        ):
            key = "authentication"
        elif any(term in text for term in ("privil", "admin", "pam", "jit", "break-glass")):
            key = "privileged_access"
        elif any(
            term in text
            for term in ("identit", "identity", "joiner", "mover", "leaver", "iam", "iag")
        ):
            key = "identity_governance"
        else:
            key = "access_control"
        if not self.domains.get(key, False):
            return False, f"domain_disabled:{key}"
        return True, "allowed"


def _bounded_integer(value: object, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
    return value


def validate_policy(payload: object) -> GuardrailPolicy:
    if not isinstance(payload, dict):
        raise ValueError("Guardrails must be an object")
    allowed = {"locked_security", "domains", "knowledge_sources", "limits", "logging"}
    if set(payload) - allowed:
        raise ValueError("Unknown guardrail setting")
    locked = payload.get("locked_security", LOCKED_CONTROLS)
    if locked != LOCKED_CONTROLS:
        raise ValueError("Fundamental security controls cannot be changed")
    raw_domains = payload.get("domains", DEFAULT_DOMAINS)
    if not isinstance(raw_domains, dict) or set(raw_domains) != set(DEFAULT_DOMAINS):
        raise ValueError("All supported guardrail domains are required")
    if any(not isinstance(value, bool) for value in raw_domains.values()):
        raise ValueError("Guardrail domains must be booleans")
    raw_sources = payload.get("knowledge_sources", {})
    if not isinstance(raw_sources, dict) or set(raw_sources) - {"mode", "publishers"}:
        raise ValueError("Invalid knowledge source policy")
    mode = raw_sources.get("mode", "all_verified")
    if mode not in {"all_verified", "selected"}:
        raise ValueError("Knowledge source mode must be all_verified or selected")
    publishers = raw_sources.get("publishers", [])
    if (
        not isinstance(publishers, list)
        or any(
            not isinstance(item, str) or not item.strip() or len(item) > 100 for item in publishers
        )
        or len(publishers) > 100
    ):
        raise ValueError("Knowledge source publishers must be a bounded string array")
    raw_limits = payload.get("limits", {})
    if not isinstance(raw_limits, dict) or set(raw_limits) - {
        "max_tool_calls",
        "max_tool_rounds",
        "max_results",
        "history_messages",
        "retention_days",
    }:
        raise ValueError("Invalid guardrail limits")
    raw_logging = payload.get("logging", {})
    if not isinstance(raw_logging, dict) or set(raw_logging) - {"conversations", "tool_calls"}:
        raise ValueError("Invalid guardrail logging policy")
    if any(
        not isinstance(raw_logging.get(key, True), bool) for key in ("conversations", "tool_calls")
    ):
        raise ValueError("Guardrail logging values must be booleans")
    return GuardrailPolicy(
        domains={key: bool(raw_domains[key]) for key in DEFAULT_DOMAINS},
        source_mode=str(mode),
        enabled_publishers=tuple(dict.fromkeys(item.strip() for item in publishers)),
        max_tool_calls=_bounded_integer(
            raw_limits.get("max_tool_calls", 6), "max_tool_calls", 1, 20
        ),
        max_tool_rounds=_bounded_integer(
            raw_limits.get("max_tool_rounds", 3), "max_tool_rounds", 1, 5
        ),
        max_results=_bounded_integer(raw_limits.get("max_results", 100), "max_results", 1, 100),
        history_messages=_bounded_integer(
            raw_limits.get("history_messages", 12), "history_messages", 2, 30
        ),
        retention_days=_bounded_integer(
            raw_limits.get("retention_days", 30), "retention_days", 1, 3650
        ),
        conversation_logging=raw_logging.get("conversations", True),
        tool_logging=raw_logging.get("tool_calls", True),
    )


def load_policy(conn: Any) -> GuardrailPolicy:
    row = conn.execute(
        "SELECT value FROM system_settings WHERE key = ?", ("chatbot_guardrails",)
    ).fetchone()
    if row is None:
        return GuardrailPolicy.defaults()
    try:
        return validate_policy(json.loads(str(row["value"])))
    except (ValueError, TypeError, json.JSONDecodeError):
        return GuardrailPolicy.defaults()


def save_policy(conn: Any, policy: GuardrailPolicy) -> None:
    conn.execute(
        "INSERT INTO system_settings(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        ("chatbot_guardrails", json.dumps(policy.as_dict(), separators=(",", ":"))),
    )
    conn.commit()


def apply_policy(config: ChatbotConfig, policy: GuardrailPolicy) -> ChatbotConfig:
    return replace(
        config,
        max_tool_calls=policy.max_tool_calls,
        max_tool_rounds=policy.max_tool_rounds,
        max_result_items=policy.max_results,
        max_history_messages=policy.history_messages,
        trace_retention_days=policy.retention_days,
        store_message_content=config.store_message_content and policy.conversation_logging,
        log_conversations=config.log_conversations and policy.conversation_logging,
        log_tool_calls=config.log_tool_calls and policy.tool_logging,
    )
