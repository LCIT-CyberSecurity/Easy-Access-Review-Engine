from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from access_review_engine.chatbot.config import ChatbotConfig
from access_review_engine.chatbot.context import AuthorizationContext, UIHints
from access_review_engine.chatbot.conversation import ConversationStore
from access_review_engine.chatbot.observability.audit import record as record_audit
from access_review_engine.chatbot.observability.traces import record as record_trace
from access_review_engine.chatbot.prompts import (
    ASSISTANT_PROMPT_VERSION,
    SCOPE_POLICY_VERSION,
    SECURITY_POLICY_VERSION,
    TOOL_POLICY_VERSION,
)
from access_review_engine.chatbot.providers.base import LLMProvider, ProviderResult
from access_review_engine.chatbot.providers.openai import OpenAIProvider, ProviderError
from access_review_engine.chatbot.safety.builtin import BuiltInSafetyProvider
from access_review_engine.chatbot.schemas import AssistantResponse
from access_review_engine.chatbot.scope import classify
from access_review_engine.chatbot.security.output_guard import validate_action
from access_review_engine.chatbot.tools.registry import (
    TOOL_FUNCTIONS,
    TOOL_SCHEMAS,
    allowed_actions,
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
        self.provider = provider or OpenAIProvider(self.config)

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
        hints = hints or UIHints()
        safe_question, intent, secret_redacted = self.safety.check_input(question)
        context = self._context(principal)
        with self.repo_factory() as repo:
            if secret_redacted:
                record_audit(
                    repo,
                    "chatbot.secret_redacted",
                    context.username,
                    {"conversation_id": conversation_id},
                )
            if intent == "OUT_OF_SCOPE":
                record_audit(repo, "chatbot.out_of_scope", context.username, {})
                return AssistantResponse(
                    OUT_OF_SCOPE, intent, security_state="out_of_scope"
                ).as_dict()
            if intent == "SUSPICIOUS":
                record_audit(repo, "chatbot.prompt_injection_suspected", context.username, {})
                return AssistantResponse(SUSPICIOUS, intent, security_state="suspicious").as_dict()
            store = ConversationStore(repo, context.subject)
            conversation_id = store.get_or_create(conversation_id)
            store.append(conversation_id, "user", safe_question)
            if not self.config.enabled:
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
                actions = (validate_action(action_id, label, allowed_actions()),)
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
                    "provider": self.config.provider,
                    "model": self.config.model,
                    "intent": intent,
                    "prompt_version": ASSISTANT_PROMPT_VERSION,
                    "scope_policy_version": SCOPE_POLICY_VERSION,
                    "tool_policy_version": TOOL_POLICY_VERSION,
                    "security_policy_version": SECURITY_POLICY_VERSION,
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
                    record_audit(repo, "chatbot.tool_denied", context.username, {"tool": call.name})
                    raise ValueError("Unknown tool")
                if set(call.arguments) - {"campaign_id"} or (
                    "campaign_id" in call.arguments
                    and not isinstance(call.arguments["campaign_id"], str)
                ):
                    record_audit(
                        repo,
                        "chatbot.tool_denied",
                        context.username,
                        {"tool": call.name, "reason": "invalid_arguments"},
                    )
                    raise ValueError("Invalid tool arguments")
                # Context is reconstructed by the API on every request and passed to every call.
                projected = function(repo, call.arguments, context, hints)
                record_audit(
                    repo,
                    "chatbot.tool_allowed",
                    context.username,
                    {"tool": call.name, "result_count": len(projected)},
                )
                messages.append(
                    {
                        "type": "function_call",
                        "call_id": call.call_id,
                        "name": call.name,
                        "arguments": call.arguments,
                    }
                )
                messages.append(
                    {"type": "function_call_output", "call_id": call.call_id, "output": projected}
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
        return classify(question)

    def validate_configuration(self) -> None:
        return None

    def healthcheck(self) -> bool:
        return True
