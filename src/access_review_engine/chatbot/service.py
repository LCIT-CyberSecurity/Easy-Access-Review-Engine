from __future__ import annotations

import json
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from access_review_engine.chatbot.config import ChatbotConfig
from access_review_engine.chatbot.context import AuthorizationContext, UIHints
from access_review_engine.chatbot.conversation import (
    ConversationStore,
    cleanup_expired_chatbot_data_periodically,
)
from access_review_engine.chatbot.observability.audit import record as record_audit
from access_review_engine.chatbot.observability.traces import record as record_trace
from access_review_engine.chatbot.prompts import (
    ASSISTANT_PROMPT_VERSION,
    SCOPE_POLICY_VERSION,
    SECURITY_POLICY_VERSION,
    TOOL_POLICY_VERSION,
)
from access_review_engine.chatbot.providers.base import LLMProvider, ProviderResult
from access_review_engine.chatbot.providers.openai import ProviderError
from access_review_engine.chatbot.providers.registry import build_provider
from access_review_engine.chatbot.safety.builtin import BuiltInSafetyProvider
from access_review_engine.chatbot.schemas import AssistantResponse
from access_review_engine.chatbot.scope import classify
from access_review_engine.chatbot.security.output_guard import validate_action
from access_review_engine.chatbot.tools.registry import (
    TOOL_FUNCTIONS,
    TOOL_SCHEMAS,
    allowed_actions,
    bound_tool_output,
    campaign_summary,
)
from access_review_engine.storage import Repository

OUT_OF_SCOPE = (
    "Je suis l'assistant EARE. Je peux vous aider à utiliser le produit, comprendre vos "
    "campagnes, vos revues, votre Golden Source et vos résultats."
)
SUSPICIOUS = "Je peux uniquement aider à comprendre et utiliser EARE dans votre périmètre autorisé."
UNAVAILABLE = "Assistant IA temporairement indisponible."


class AssistantService:
    """Orchestrates scope, authorization, safe projections and an interchangeable provider."""

    def __init__(
        self,
        repo_factory: Callable[[], Repository],
        config: ChatbotConfig | None = None,
        provider: LLMProvider | None = None,
    ) -> None:
        self.repo_factory = repo_factory
        self.config = config or ChatbotConfig.from_env()
        self.safety = BuiltInSafetyProvider(self.config)
        self.provider_error: ProviderError | None = None
        if provider is not None:
            self.provider = provider
        else:
            try:
                self.provider = build_provider(self.config)
            except ProviderError as exc:
                self.provider = None
                self.provider_error = exc
        self._tool_events: list[dict[str, str]] = []

    @staticmethod
    def _context(principal: Any) -> AuthorizationContext:
        return AuthorizationContext(
            str(principal.subject),
            str(principal.username),
            str(principal.role),
            frozenset(principal.scopes),
        )

    def handle(
        self,
        principal: Any,
        question: str,
        conversation_id: str | None = None,
        hints: UIHints | None = None,
        principal_resolver: Callable[[], Any] | None = None,
    ) -> dict[str, Any]:
        started = time.monotonic()
        self._tool_events = []
        hints = hints or UIHints()
        safe_question, intent, secret_redacted = self.safety.check_input(question, hints.route)
        context = self._context(principal)
        with self.repo_factory() as repo:
            cleanup_expired_chatbot_data_periodically(repo, self.config.trace_retention_days)
            store = ConversationStore(repo, context.subject)
            # Validate a supplied conversation before classification so an out-of-scope
            # message cannot be used to probe another user's conversation.
            if conversation_id:
                store.get_or_create(conversation_id)
            if secret_redacted:
                record_audit(
                    repo,
                    "chatbot.secret_redacted",
                    context.username,
                    {"conversation_id": conversation_id},
                )
            if intent == "OUT_OF_SCOPE":
                record_audit(repo, "chatbot.out_of_scope", context.username, {})
                record_trace(repo, {
                    "id": str(uuid.uuid4()), "user_id": context.subject,
                    "question": safe_question[:2000], "answer": OUT_OF_SCOPE,
                    "provider": "none", "model": None, "intent": intent,
                    "security_flags": ["out_of_scope"], "tools_called": [],
                    "tools_denied": [], "created_at": datetime.now(UTC).isoformat(),
                })
                return AssistantResponse(
                    OUT_OF_SCOPE, intent, security_state="out_of_scope"
                ).as_dict()
            if intent == "SUSPICIOUS":
                record_audit(repo, "chatbot.prompt_injection_suspected", context.username, {})
                record_trace(repo, {
                    "id": str(uuid.uuid4()), "user_id": context.subject,
                    "question": safe_question[:2000], "answer": SUSPICIOUS,
                    "provider": "none", "model": None, "intent": intent,
                    "security_flags": ["suspicious"], "tools_called": [],
                    "tools_denied": [], "created_at": datetime.now(UTC).isoformat(),
                })
                return AssistantResponse(SUSPICIOUS, intent, security_state="suspicious").as_dict()
            conversation_id = store.get_or_create(conversation_id)
            store.append(conversation_id, "user", safe_question)
            if not self.config.enabled or self.provider is None:
                record_audit(
                    repo, "chatbot.provider_error", context.username, {"reason": "disabled"}
                )
                return {
                    **AssistantResponse(
                        UNAVAILABLE, intent, security_state="unavailable"
                    ).as_dict(),
                    "conversation_id": conversation_id,
                }
            security_state = "ok"
            try:
                result = self._generate(
                    repo,
                    context,
                    store,
                    conversation_id,
                    safe_question,
                    intent,
                    hints,
                    principal_resolver,
                )
                answer = self.safety.check_output(
                    result.text or "Je n'ai pas trouvé de donnée disponible dans votre périmètre."
                )
            except (ProviderError, ValueError, PermissionError) as exc:
                record_audit(
                    repo,
                    "chatbot.provider_error"
                    if isinstance(exc, ProviderError)
                    else "chatbot.tool_denied",
                    context.username,
                    {"conversation_id": conversation_id},
                )
                answer = UNAVAILABLE
                result = ProviderResult()
                security_state = "unavailable"
            store.append(conversation_id, "assistant", answer)
            action_by_intent = {
                "EARE_DASHBOARD": ("OPEN_ACTIONS", "Voir les actions"),
                "EARE_CAMPAIGN": ("OPEN_CAMPAIGN", "Voir les campagnes"),
                "EARE_GOLDEN": ("OPEN_GOLDEN", "Ouvrir la Golden Source"),
                "EARE_REVIEW": ("OPEN_PENDING_REVIEWS", "Voir les revues en attente"),
                "EARE_SOURCE": ("OPEN_SOURCES", "Voir les sources"),
                "EARE_REPORT": ("OPEN_REPORTS", "Voir les rapports"),
            }
            actions = ()
            if intent in action_by_intent:
                action_id, label = action_by_intent[intent]
                route = self._resolve_action(repo, action_id, context, hints)
                if route is not None and action_id in allowed_actions(context):
                    actions = (validate_action(action_id, label, allowed_actions(context), route),)
            response = AssistantResponse(
                answer, intent, actions=actions, security_state=security_state
            ).as_dict()
            response["conversation_id"] = conversation_id
            record_trace(
                repo,
                {
                    "id": str(uuid.uuid4()),
                    "conversation_id": conversation_id,
                    "user_id": context.subject,
                    "question": safe_question[:2000],
                    "answer": answer[:4000],
                    "provider": (
                        self.config.provider if self.provider is not None else "unsupported"
                    ),
                    "model": self.config.model,
                    "intent": intent,
                    "prompt_version": ASSISTANT_PROMPT_VERSION,
                    "scope_policy_version": SCOPE_POLICY_VERSION,
                    "tool_policy_version": TOOL_POLICY_VERSION,
                    "security_policy_version": SECURITY_POLICY_VERSION,
                    "tools_called": [
                        event["tool"] for event in self._tool_events if event["status"] == "allowed"
                    ],
                    "tools_denied": [
                        event for event in self._tool_events if event["status"] == "denied"
                    ],
                    "input_tokens": result.usage.get("input_tokens"),
                    "output_tokens": result.usage.get("output_tokens"),
                    "security_flags": [security_state] if security_state != "ok" else [],
                    "latency_ms": int((time.monotonic() - started) * 1000),
                    "created_at": datetime.now(UTC).isoformat(),
                },
            )
            record_audit(
                repo,
                "chatbot.response",
                context.username,
                {"conversation_id": conversation_id, "intent": intent},
            )
            return response

    @staticmethod
    def _resolve_action(
        repo: Repository, action_id: str, context: AuthorizationContext, hints: UIHints
    ) -> str | None:
        if action_id not in allowed_actions(context):
            return None
        if action_id == "OPEN_CAMPAIGN":
            candidate = campaign_summary(repo, {"campaign_id": hints.object_id}, context, hints)
            if candidate.get("available") and hints.object_id:
                return f"/campaigns/{hints.object_id}"
            return "/campaigns"
        return {
            "OPEN_GOLDEN": "/golden",
            "OPEN_PENDING_REVIEWS": "/reviews",
            "OPEN_ACTIONS": "/actions",
            "OPEN_SOURCES": "/sources",
            "OPEN_REPORTS": "/reports",
        }.get(action_id)

    def _generate(
        self,
        repo: Repository,
        context: AuthorizationContext,
        store: ConversationStore,
        conversation_id: str,
        question: str,
        intent: str,
        hints: UIHints,
        principal_resolver: Callable[[], Any] | None,
    ) -> ProviderResult:
        if self.provider is None:
            raise ProviderError("Assistant provider is unavailable")
        messages: list[dict[str, Any]] = [
            {"role": row["role"], "content": row["content"]}
            for row in store.history(conversation_id, self.config.max_history_messages)
        ]
        for _ in range(self.config.max_tool_rounds):
            result = self.provider.generate(messages, TOOL_SCHEMAS)
            if not result.tool_calls:
                return result
            for call in result.tool_calls:
                if principal_resolver is not None:
                    refreshed = principal_resolver()
                    if refreshed is None:
                        raise PermissionError("Session authorization changed")
                    context = self._context(refreshed)
                function = TOOL_FUNCTIONS.get(call.name)
                if function is None or not isinstance(call.arguments, dict):
                    self._tool_events.append(
                        {"tool": call.name, "status": "denied", "reason": "unknown_tool"}
                    )
                    record_audit(repo, "chatbot.tool_denied", context.username, {
                        "conversation_id": conversation_id, "tool": call.name,
                        "reason": "unknown_tool", "result_count": 0,
                    })
                    raise ValueError("Unknown tool")
                schema = next((item for item in TOOL_SCHEMAS if item["name"] == call.name), None)
                properties = set((schema or {}).get("parameters", {}).get("properties", {}))
                required = set((schema or {}).get("parameters", {}).get("required", []))
                if set(call.arguments) != properties or not required <= set(call.arguments):
                    self._tool_events.append(
                        {"tool": call.name, "status": "denied", "reason": "invalid_arguments"}
                    )
                    record_audit(
                        repo,
                        "chatbot.tool_denied",
                        context.username,
                        {
                            "conversation_id": conversation_id, "tool": call.name,
                            "reason": "invalid_arguments", "result_count": 0,
                        },
                    )
                    raise ValueError("Invalid tool arguments")
                # Context is reconstructed by the API on every request and passed to every call.
                projected = bound_tool_output(function(repo, call.arguments, context, hints))
                self._tool_events.append(
                    {"tool": call.name, "status": "allowed", "reason": "authorized"}
                )
                record_audit(
                    repo,
                    "chatbot.tool_allowed",
                    context.username,
                    {
                        "conversation_id": conversation_id, "tool": call.name,
                        "reason": "authorized", "result_count": len(projected),
                    },
                )
                for item in result.output_items:
                    if item.get("type") in {"reasoning", "function_call"}:
                        messages.append(item)
                messages.append(
                    {
                        "type": "function_call_output",
                        "call_id": call.call_id,
                        "output": json.dumps({
                            "type": "eare_data",
                            "untrusted": True,
                            "tool": call.name,
                            "data": projected,
                        }, ensure_ascii=False, separators=(",", ":")),
                    }
                )
        raise ValueError("Tool round limit exceeded")


class FakeLLMProvider:
    """Deterministic provider used by tests; it never performs network calls."""

    def __init__(self, answer: str = "Réponse EARE de test.") -> None:
        self.answer = answer
        self.calls: list[list[dict[str, Any]]] = []

    def generate(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> ProviderResult:
        self.calls.append(messages)
        return ProviderResult(text=self.answer)

    def classify(self, question: str, route: str) -> str:
        return classify(question, route)

    def validate_configuration(self) -> None:
        return None

    def healthcheck(self) -> bool:
        return True
