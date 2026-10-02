from __future__ import annotations

import json
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from access_review_engine.chatbot.config import ChatbotConfig
from access_review_engine.chatbot.context import AuthorizationContext, UIHints, resolve_ui_context
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
from access_review_engine.chatbot.providers.base import LLMProvider, ProviderResult, ToolCall
from access_review_engine.chatbot.providers.openai import ProviderError
from access_review_engine.chatbot.providers.registry import build_provider
from access_review_engine.chatbot.safety.builtin import BuiltInSafetyProvider
from access_review_engine.chatbot.schemas import AssistantAction, AssistantBrief, AssistantResponse
from access_review_engine.chatbot.scope import classify
from access_review_engine.chatbot.security.output_guard import validate_action
from access_review_engine.chatbot.security.tool_policy import validate_tool_arguments
from access_review_engine.chatbot.tools.registry import (
    TOOL_FUNCTIONS,
    TOOL_SCHEMAS,
    allowed_actions,
    bound_tool_output,
    campaign_summary,
    dashboard,
    golden_gaps,
    guidance,
    review_progress,
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
        self.provider: LLMProvider | None
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
        hints = resolve_ui_context((hints or UIHints()).route, (hints or UIHints()).object_id)
        safe_question, intent, secret_redacted = self.safety.check_input(question, hints.route)
        context = self._context(principal)
        with self.repo_factory() as repo:
            cleanup_expired_chatbot_data_periodically(repo, self.config.trace_retention_days)
            store = ConversationStore(
                repo, context.subject, store_content=self.config.store_message_content
            )
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
                self._record_trace(repo, self._early_trace(
                    context, conversation_id, safe_question, OUT_OF_SCOPE, intent, "out_of_scope"
                ))
                return AssistantResponse(
                    OUT_OF_SCOPE, intent, security_state="out_of_scope"
                ).as_dict()
            if intent == "SUSPICIOUS":
                record_audit(repo, "chatbot.prompt_injection_suspected", context.username, {})
                self._record_trace(repo, self._early_trace(
                    context, conversation_id, safe_question, SUSPICIOUS, intent, "suspicious"
                ))
                return AssistantResponse(SUSPICIOUS, intent, security_state="suspicious").as_dict()
            conversation_id = store.get_or_create(conversation_id)
            store.append(conversation_id, "user", safe_question)
            brief = self.build_brief(repo, context, hints) if intent == "EARE_REPORT" else None
            if not self.config.enabled or self.provider is None:
                record_audit(
                    repo, "chatbot.provider_error", context.username, {"reason": "disabled"}
                )
                return {
                    **AssistantResponse(
                        UNAVAILABLE, intent, optional_document=brief,
                        security_state="unavailable"
                    ).as_dict(),
                    "conversation_id": conversation_id,
                }
            security_state = "ok"
            try:
                result, context = self._generate(
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
            actions: tuple[AssistantAction, ...] = ()
            if intent in action_by_intent:
                action_id, label = action_by_intent[intent]
                route = self._resolve_action(repo, action_id, context, hints)
                if route is not None and action_id in allowed_actions(context):
                    actions = (validate_action(action_id, label, allowed_actions(context), route),)
            response = AssistantResponse(
                answer, intent, actions=actions, optional_document=brief,
                security_state=security_state,
            ).as_dict()
            response["conversation_id"] = conversation_id
            self._record_trace(
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
        raise AssertionError("Assistant request completed without a response")

    def _record_trace(self, repo: Repository, payload: dict[str, Any]) -> None:
        if not self.config.log_conversations or not self.config.store_message_content:
            payload = {**payload, "question": None, "answer": None}
        if not self.config.log_tool_calls:
            payload = {**payload, "tools_called": [], "tools_denied": []}
        record_trace(repo, payload)

    @staticmethod
    def _early_trace(
        context: AuthorizationContext,
        conversation_id: str | None,
        question: str,
        answer: str,
        intent: str,
        security_flag: str,
    ) -> dict[str, Any]:
        return {
            "id": str(uuid.uuid4()), "conversation_id": conversation_id,
            "message_id": None, "user_id": context.subject,
            "question": question[:2000], "answer": answer[:4000],
            "provider": "none", "model": None, "intent": intent,
            "prompt_version": ASSISTANT_PROMPT_VERSION,
            "scope_policy_version": SCOPE_POLICY_VERSION,
            "tool_policy_version": TOOL_POLICY_VERSION,
            "security_policy_version": SECURITY_POLICY_VERSION,
            "tools_called": [], "tools_denied": [],
            "input_tokens": None, "output_tokens": None,
            "security_flags": [security_flag],
            "latency_ms": 0, "created_at": datetime.now(UTC).isoformat(),
        }

    @staticmethod
    def build_brief(
        repo: Repository, context: AuthorizationContext, hints: UIHints
    ) -> AssistantBrief:
        summary = dashboard(repo, {}, context, hints)
        progress = review_progress(repo, {}, context, hints)
        gaps = golden_gaps(repo, {}, context, hints)
        guidance_result = guidance(repo, {}, context, hints)
        metrics = {
            "campaigns": summary["campaigns"],
            "pending_reviews": progress["pending"],
            "decided_reviews": progress["decided"],
            "open_actions": summary["open_actions"],
            "golden_sources": gaps["golden_sources"],
            "golden_rows_considered": gaps["rows_considered"],
        }
        findings = tuple(
            f"{name}: {value}"
            for name, value in gaps["gaps"].items()
            if isinstance(value, int) and value > 0
        )
        recommendations = tuple(
            str(item.get("title") or item.get("description") or item.get("id"))
            for item in guidance_result.get("recommendations", [])[:5]
        )
        return AssistantBrief(
            title="Synthèse EARE",
            generated_at=datetime.now(UTC).isoformat(),
            scope=f"role={context.role}; user={context.username}",
            executive_summary="Synthèse calculée uniquement à partir des projections autorisées.",
            metrics=metrics,
            findings=findings,
            recommendations=recommendations,
        )

    @staticmethod
    def render_brief_markdown(brief: AssistantBrief) -> str:
        lines = [
            f"# {brief.title}", "", f"- Generated at: {brief.generated_at}",
            f"- Scope: {brief.scope}", "", brief.executive_summary, "", "## Metrics",
        ]
        lines.extend(f"- {key}: {value}" for key, value in brief.metrics.items())
        if brief.findings:
            lines.extend(["", "## Findings", *[f"- {item}" for item in brief.findings]])
        if brief.recommendations:
            lines.extend([
                "", "## Recommendations", *[f"- {item}" for item in brief.recommendations]
            ])
        return "\n".join(lines) + "\n"

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
    ) -> tuple[ProviderResult, AuthorizationContext]:
        if self.provider is None:
            raise ProviderError("Assistant provider is unavailable")
        messages: list[dict[str, Any]] = [
            {"role": row["role"], "content": row["content"]}
            for row in store.history(conversation_id, self.config.max_history_messages)
        ]
        # Keep the active question in memory even when durable message content is disabled.
        if not messages or messages[-1] != {"role": "user", "content": question}:
            messages.append({"role": "user", "content": question})
        input_tokens = 0
        output_tokens = 0
        tool_call_count = 0
        for _ in range(self.config.max_tool_rounds):
            context_size = len(json.dumps(messages, ensure_ascii=False, default=str))
            if context_size > self.config.max_context_chars:
                raise ValueError("Assistant context limit exceeded")
            result = self.provider.generate(messages, TOOL_SCHEMAS)
            input_tokens += int(result.usage.get("input_tokens", 0) or 0)
            output_tokens += int(result.usage.get("output_tokens", 0) or 0)
            if not result.tool_calls:
                return ProviderResult(
                    text=result.text,
                    tool_calls=result.tool_calls,
                    usage={"input_tokens": input_tokens, "output_tokens": output_tokens},
                    output_items=result.output_items,
                ), context
            pending_outputs: list[tuple[ToolCall, dict[str, Any]]] = []
            call_ids: set[str] = set()
            for call in result.tool_calls:
                tool_call_count += 1
                if tool_call_count > self.config.max_tool_calls:
                    self._tool_events.append(
                        {"tool": call.name, "status": "denied", "reason": "tool_call_limit"}
                    )
                    record_audit(repo, "chatbot.tool_denied", context.username, {
                        "conversation_id": conversation_id, "tool": call.name,
                        "reason": "tool_call_limit", "result_count": 0,
                    })
                    raise ValueError("Tool call limit exceeded")
                if not call.call_id or call.call_id in call_ids:
                    raise ProviderError("Assistant returned invalid tool call id")
                call_ids.add(call.call_id)
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
                if schema is None or not validate_tool_arguments(call.arguments, schema):
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
                projected = bound_tool_output(
                    function(repo, call.arguments, context, hints),
                    max_items=self.config.max_result_items,
                )
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
                pending_outputs.append((call, projected))
            messages.extend(
                item for item in result.output_items
                if item.get("type") in {"reasoning", "function_call"}
            )
            for call, projected in pending_outputs:
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
