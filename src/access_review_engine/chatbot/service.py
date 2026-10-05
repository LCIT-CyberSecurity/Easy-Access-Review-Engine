from __future__ import annotations

import json
import re
import time
import uuid
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from access_review_engine.chatbot.config import ChatbotConfig
from access_review_engine.chatbot.context import AuthorizationContext, UIHints, resolve_ui_context
from access_review_engine.chatbot.conversation import (
    ConversationStore,
    cleanup_expired_chatbot_data_periodically,
)
from access_review_engine.chatbot.guardrails import GuardrailPolicy
from access_review_engine.chatbot.observability.audit import record as record_audit
from access_review_engine.chatbot.observability.traces import record as record_trace
from access_review_engine.chatbot.prompts import (
    CHATBOT_PROMPT_VERSION,
    SCOPE_POLICY_VERSION,
    SECURITY_POLICY_VERSION,
    TOOL_POLICY_VERSION,
)
from access_review_engine.chatbot.providers.base import (
    LLMProvider,
    ProviderHealth,
    ProviderResult,
    ToolCall,
)
from access_review_engine.chatbot.providers.openai import ProviderError
from access_review_engine.chatbot.providers.registry import build_provider
from access_review_engine.chatbot.safety.builtin import BuiltInSafetyProvider
from access_review_engine.chatbot.schemas import (
    AssistantAction,
    AssistantBrief,
    AssistantResponse,
    AssistantSource,
)
from access_review_engine.chatbot.scope import classify
from access_review_engine.chatbot.security.output_guard import validate_action
from access_review_engine.chatbot.security.tool_policy import validate_tool_arguments
from access_review_engine.chatbot.tools.knowledge import search_access_control_knowledge
from access_review_engine.chatbot.tools.registry import (
    TOOL_FUNCTIONS,
    TOOL_SCHEMAS,
    allowed_actions,
    bound_tool_output,
    campaign_summary,
    dashboard,
    find_authorized_campaign,
    golden_gaps,
    guidance,
    review_progress,
)
from access_review_engine.chatbot.tools.semantic import (
    get_authentication_posture_summary,
    search_authorized_accesses,
    search_authorized_campaigns,
    search_authorized_identities,
    search_authorized_remediations,
    search_authorized_reviews,
)
from access_review_engine.storage import Repository

OUT_OF_SCOPE = (
    "Hors périmètre du Chatbot EARE\n\n"
    "Cette question n'est pas directement liée à EARE ou au contrôle d'accès.\n\n"
    "Je peux vous aider sur les identités, habilitations, revues d'accès, accès privilégiés, "
    "comptes techniques, authentification, MFA, moindre privilège, IAM/IAG et les bonnes "
    "pratiques associées."
)
SUSPICIOUS = "Je peux uniquement aider à comprendre et utiliser EARE dans votre périmètre autorisé."
UNAVAILABLE = "Chatbot IA temporairement indisponible."
EMPTY_PROVIDER = "Je n'ai pas pu générer une réponse exploitable à cette question."


class AssistantService:
    """Orchestrates scope, authorization, safe projections and an interchangeable provider."""

    def __init__(
        self,
        repo_factory: Callable[[], Repository],
        config: ChatbotConfig | None = None,
        provider: LLMProvider | None = None,
        policy: GuardrailPolicy | None = None,
    ) -> None:
        self.repo_factory = repo_factory
        self.config = config or ChatbotConfig.from_env()
        self.policy = policy or GuardrailPolicy.defaults()
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
        self._sources_used: list[AssistantSource] = []
        self._available_sources: dict[str, dict[str, Any]] = {}

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
        self._sources_used = []
        self._available_sources = {}
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
                self._record_trace(
                    repo,
                    self._early_trace(
                        context,
                        conversation_id,
                        safe_question,
                        OUT_OF_SCOPE,
                        intent,
                        "out_of_scope",
                    ),
                )
                return AssistantResponse(
                    OUT_OF_SCOPE, intent, security_state="out_of_scope"
                ).as_dict()
            if intent == "SUSPICIOUS":
                record_audit(repo, "chatbot.prompt_injection_suspected", context.username, {})
                self._record_trace(
                    repo,
                    self._early_trace(
                        context, conversation_id, safe_question, SUSPICIOUS, intent, "suspicious"
                    ),
                )
                return AssistantResponse(SUSPICIOUS, intent, security_state="suspicious").as_dict()
            guardrail_allowed, guardrail_reason = self.policy.allows(intent, safe_question)
            if not guardrail_allowed:
                record_audit(
                    repo,
                    "chatbot.guardrail_denied",
                    context.username,
                    {
                        "reason": guardrail_reason,
                    },
                )
                self._record_trace(
                    repo,
                    {
                        **self._early_trace(
                            context,
                            conversation_id,
                            safe_question,
                            OUT_OF_SCOPE,
                            intent,
                            "out_of_scope",
                        ),
                        "guardrail_state": "out_of_scope",
                        "guardrail_reason": guardrail_reason,
                    },
                )
                return AssistantResponse(
                    OUT_OF_SCOPE, "OUT_OF_SCOPE", security_state="out_of_scope"
                ).as_dict()
            conversation_id = store.get_or_create(conversation_id)
            store.append(conversation_id, "user", safe_question)
            brief = (
                self.build_brief(repo, context, hints, safe_question)
                if intent == "EARE_REPORT"
                else None
            )
            if not self.config.enabled or self.provider is None:
                record_audit(
                    repo, "chatbot.provider_error", context.username, {"reason": "disabled"}
                )
                return {
                    **AssistantResponse(
                        UNAVAILABLE, intent, optional_document=brief, security_state="unavailable"
                    ).as_dict(),
                    "conversation_id": conversation_id,
                }
            security_state = "ok"
            provider_error_category: str | None = None
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
                if not isinstance(result.text, str) or not result.text.strip():
                    answer = EMPTY_PROVIDER
                    security_state = "empty_provider_response"
                    record_audit(
                        repo,
                        "chatbot.empty_provider_response",
                        context.username,
                        {"conversation_id": conversation_id},
                    )
                else:
                    answer = self.safety.check_output(result.text)
            except (ProviderError, ValueError, PermissionError) as exc:
                if isinstance(exc, ProviderError):
                    audit_event = "chatbot.provider_error"
                    failure_state = "unavailable"
                    error_category = exc.category
                    provider_error_category = exc.category
                elif isinstance(exc, PermissionError):
                    audit_event = "chatbot.authorization_changed"
                    failure_state = "authorization_changed"
                    error_category = "authorization_changed"
                else:
                    audit_event = "chatbot.tool_validation_error"
                    failure_state = "tool_validation_error"
                    error_category = "tool_validation_error"
                record_audit(
                    repo,
                    audit_event,
                    context.username,
                    {
                        "conversation_id": conversation_id,
                        "category": error_category,
                    },
                )
                answer = UNAVAILABLE
                result = ProviderResult()
                security_state = failure_state
                self._sources_used = []
            store.append(conversation_id, "assistant", answer)
            action_by_intent = {
                "EARE_DASHBOARD": ("OPEN_ACTIONS", "Voir les actions"),
                "EARE_CAMPAIGN": ("OPEN_CAMPAIGN", "Voir les campagnes"),
                "EARE_GOLDEN": ("OPEN_GOLDEN", "Ouvrir la Golden Source"),
                "EARE_REVIEW": ("OPEN_PENDING_REVIEWS", "Voir les revues en attente"),
                "EARE_SOURCE": ("OPEN_SOURCES", "Voir les sources"),
                "EARE_REPORT": ("OPEN_REPORTS", "Voir les rapports"),
            }
            if intent in {"EARE_NAVIGATION", "EARE_USAGE", "EARE_ACCESS_GUIDANCE"}:
                navigation_action = self._navigation_action(safe_question)
                if navigation_action is not None:
                    action_by_intent[intent] = navigation_action
            actions: tuple[AssistantAction, ...] = ()
            if intent in action_by_intent:
                action_id, label = action_by_intent[intent]
                route = self._resolve_action(repo, action_id, context, hints, safe_question)
                if route is not None and action_id in allowed_actions(context):
                    actions = (validate_action(action_id, label, allowed_actions(context), route),)
            response = AssistantResponse(
                answer,
                intent,
                actions=actions,
                optional_document=brief,
                sources=tuple(self._sources_used),
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
                    "prompt_version": CHATBOT_PROMPT_VERSION,
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
                    "source_ids_used": [source.id for source in self._sources_used],
                    "guardrail_state": "allowed" if security_state == "ok" else security_state,
                    "guardrail_reason": "allowed" if security_state == "ok" else security_state,
                    "provider_error_category": provider_error_category,
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
            "id": str(uuid.uuid4()),
            "conversation_id": conversation_id,
            "message_id": None,
            "user_id": context.subject,
            "question": question[:2000],
            "answer": answer[:4000],
            "provider": "none",
            "model": None,
            "intent": intent,
            "prompt_version": CHATBOT_PROMPT_VERSION,
            "scope_policy_version": SCOPE_POLICY_VERSION,
            "tool_policy_version": TOOL_POLICY_VERSION,
            "security_policy_version": SECURITY_POLICY_VERSION,
            "tools_called": [],
            "tools_denied": [],
            "input_tokens": None,
            "output_tokens": None,
            "security_flags": [security_flag],
            "guardrail_state": security_flag,
            "guardrail_reason": security_flag,
            "latency_ms": 0,
            "created_at": datetime.now(UTC).isoformat(),
        }

    def build_brief(
        self,
        repo: Repository,
        context: AuthorizationContext,
        hints: UIHints,
        question: str = "",
    ) -> AssistantBrief:
        summary = dashboard(repo, {}, context, hints)
        progress = review_progress(repo, {}, context, hints)
        gaps = golden_gaps(repo, {}, context, hints)
        guidance_result = guidance(repo, {}, context, hints)
        perimeter = next(
            (
                row
                for row in repo.list_payloads("information_systems")
                if str(row.get("name") or "").casefold() in question.casefold()
            ),
            None,
        )
        access_args: dict[str, Any] = {"limit": self.config.max_result_items}
        identity_args: dict[str, Any] = {"limit": self.config.max_result_items}
        if perimeter is not None:
            perimeter_ids = [str(perimeter.get("id"))]
            access_args["information_system_ids"] = perimeter_ids
            identity_args["information_system_ids"] = perimeter_ids
        access_result = search_authorized_accesses(repo, access_args, context, hints)
        identity_result = search_authorized_identities(repo, identity_args, context, hints)
        providers = [str(provider) for provider in access_result.get("providers", [])]
        perimeter_filter = (
            {"information_system_ids": [str(perimeter.get("id"))]} if perimeter is not None else {}
        )
        campaigns = search_authorized_campaigns(
            repo, {**perimeter_filter, "limit": self.config.max_result_items}, context, hints
        )
        reviews = search_authorized_reviews(
            repo, {**perimeter_filter, "limit": self.config.max_result_items}, context, hints
        )
        remediations = search_authorized_remediations(
            repo, {**perimeter_filter, "limit": self.config.max_result_items}, context, hints
        )
        authentication_rows = []
        for provider_name in providers:
            posture = get_authentication_posture_summary(
                repo, {"provider": provider_name}, context, hints
            )
            authentication_rows.extend(posture.get("providers", []))
        knowledge: dict[str, Any] = {"items": [], "sources": [], "count": 0}
        if self.policy.domains.get("external_guidance", False):
            knowledge = search_access_control_knowledge(
                repo,
                {
                    "query": (
                        "least privilege privileged accounts access review "
                        "ownership authentication"
                    ),
                    "publishers": (
                        list(self.policy.enabled_publishers)
                        if self.policy.source_mode == "selected"
                        else []
                    ),
                    "limit": 3,
                },
                context,
                hints,
            )
        if self.policy.source_mode == "selected" and not self.policy.enabled_publishers:
            knowledge = {"items": [], "sources": [], "count": 0}
        self._capture_sources(
            knowledge,
            {
                str(source_id)
                for item in knowledge.get("items", [])
                if isinstance(item, dict)
                for source_id in item.get("source_ids", [])
            },
        )
        metrics = {
            "campaigns": summary["campaigns"],
            "pending_reviews": progress["pending"],
            "decided_reviews": progress["decided"],
            "open_actions": summary["open_actions"],
            "golden_sources": gaps["golden_sources"],
            "golden_rows_considered": gaps["rows_considered"],
        }
        findings = (
            tuple(
                f"{name}: {value}"
                for name, value in gaps["gaps"].items()
                if isinstance(value, int) and value > 0
            )
            if perimeter is None
            else ()
        )
        recommendations = tuple(
            str(item.get("title") or item.get("description") or item.get("id"))
            for item in guidance_result.get("recommendations", [])[:5]
        ) + tuple(str(item.get("summary")) for item in knowledge.get("items", [])[:3])
        authentication = Counter(str(row.get("state") or "unknown") for row in authentication_rows)
        access_count_args = {key: value for key, value in access_args.items() if key != "limit"}
        identity_count_args = {key: value for key, value in identity_args.items() if key != "limit"}
        access_completeness = {
            state: search_authorized_accesses(
                repo, {**access_count_args, "completeness": state, "limit": 1}, context, hints
            )["count"]
            for state in ("complete", "partial", "not_defined")
        }
        access_completeness = {key: value for key, value in access_completeness.items() if value}
        review_rows = reviews["items"]
        remediation_rows = remediations["items"]
        campaign_rows = campaigns["items"]
        review_count = int(reviews["count"])
        remediation_count = int(remediations["count"])
        campaign_count: int | None = int(campaigns["count"])
        campaign_truncated = bool(campaigns["truncated"])
        classification_groups: Counter[str] = Counter(
            str(row.get("classification") or "unknown") for row in review_rows
        )
        sections: dict[str, Any] = {}
        if identity_result["count"]:
            sections["identities"] = {
                "count": identity_result["count"],
                "technical_accounts": search_authorized_identities(
                    repo,
                    {**identity_count_args, "identity_type": "technical_account", "limit": 1},
                    context,
                    hints,
                )["count"],
                "shared_accounts": search_authorized_identities(
                    repo,
                    {**identity_count_args, "identity_type": "shared_account", "limit": 1},
                    context,
                    hints,
                )["count"],
                "privileged_accounts": search_authorized_identities(
                    repo,
                    {**identity_count_args, "privileged_access": True, "limit": 1},
                    context,
                    hints,
                )["count"],
            }
        if access_result["count"]:
            sections["accesses"] = {
                "count": access_result["count"],
                "privileged": search_authorized_accesses(
                    repo, {**access_count_args, "privileged": True, "limit": 1}, context, hints
                )["count"],
                "without_owner": search_authorized_accesses(
                    repo, {**access_count_args, "owner_state": "missing", "limit": 1}, context, hints
                )["count"],
                "by_completeness": dict(sorted(access_completeness.items())),
            }
        if authentication_rows:
            sections["authentication_posture"] = {
                "providers": len(authentication_rows),
                "by_state": dict(sorted(authentication.items())),
                "note": "not_collected does not mean that MFA or another control is disabled",
            }
        # Reviews, campaigns and remediations are already filtered by their linked
        # review/access perimeter; provider facets must not widen an SI report.
        providers_truncated = False
        if review_count and not (perimeter is not None and providers_truncated):
            sections["reviews"] = {
                "count": review_count,
                "by_classification": dict(sorted(classification_groups.items())),
            }
        if remediation_count and not (perimeter is not None and providers_truncated):
            sections["remediations"] = {"count": remediation_count}
        if campaign_rows:
            sections["campaigns"] = (
                {"items_returned": len(campaign_rows), "truncated": True}
                if campaign_count is None or providers_truncated
                else {"count": campaign_count}
            )
        if perimeter is not None and providers_truncated:
            sections["limitations"] = {
                "reason": "provider facet limit reached",
                "provider_count": access_result.get("provider_count"),
            }
        if perimeter is not None:
            metrics = {
                "accesses": access_result["count"],
                "identities": identity_result["count"],
                "reviews": review_count if not providers_truncated else "truncated",
                "campaigns": (
                    campaign_count
                    if campaign_count is not None and not providers_truncated
                    else "truncated"
                ),
                "remediations": remediation_count if not providers_truncated else "truncated",
            }
        return AssistantBrief(
            title=(
                f"Rapport de contrôle d'accès — {perimeter.get('name')}"
                if perimeter is not None
                else "Synthèse EARE"
            ),
            generated_at=datetime.now(UTC).isoformat(),
            scope=(
                f"Information System: {perimeter.get('name')}"
                if perimeter is not None
                else f"role={context.role}; user={context.username}"
            ),
            executive_summary="Synthèse calculée uniquement à partir des projections autorisées.",
            metrics=metrics,
            findings=findings,
            recommendations=recommendations,
            sources=tuple(self._sources_used),
            sections=sections,
        )

    @staticmethod
    def render_brief_markdown(brief: AssistantBrief) -> str:
        lines = [
            f"# {brief.title}",
            "",
            f"- Generated at: {brief.generated_at}",
            f"- Scope: {brief.scope}",
            "",
            brief.executive_summary,
            "",
            "## Metrics",
        ]
        lines.extend(f"- {key}: {value}" for key, value in brief.metrics.items())
        if brief.findings:
            lines.extend(["", "## Findings", *[f"- {item}" for item in brief.findings]])
        if brief.recommendations:
            lines.extend(
                ["", "## Recommendations", *[f"- {item}" for item in brief.recommendations]]
            )
        if brief.sections:
            lines.extend(["", "## Constats EARE"])
            for name, values in brief.sections.items():
                lines.append(f"- {name}: {json.dumps(values, ensure_ascii=False, sort_keys=True)}")
        if brief.sources:
            lines.extend(["", "## Sources et références"])
            for source in brief.sources:
                reference = f" — {source.reference}" if source.reference else ""
                url = f" — {source.url}" if source.url else ""
                lines.append(f"- {source.publisher} — {source.title}{reference}{url}")
        return "\n".join(lines) + "\n"

    @staticmethod
    def _resolve_action(
        repo: Repository,
        action_id: str,
        context: AuthorizationContext,
        hints: UIHints,
        question: str = "",
    ) -> str | None:
        if action_id not in allowed_actions(context):
            return None
        if action_id == "OPEN_CAMPAIGN":
            candidate = campaign_summary(repo, {"campaign_id": hints.object_id}, context, hints)
            if candidate.get("available") and hints.object_id:
                return f"/campaigns/{hints.object_id}"
            if any(
                term in question.casefold()
                for term in ("ouvre", "ouvrir", "open", "campagne", "campaign")
            ):
                matches = find_authorized_campaign(repo, {"query": question}, context, hints).get(
                    "matches", []
                )
                if len(matches) == 1:
                    return f"/campaigns/{matches[0]['id']}"
            return "/campaigns"
        return {
            "OPEN_GOLDEN": "/golden",
            "OPEN_PENDING_REVIEWS": "/reviews",
            "OPEN_ACTIONS": "/actions",
            "OPEN_SOURCES": "/sources",
            "OPEN_REPORTS": "/reports",
            "OPEN_PERIMETERS": "/perimeters",
            "OPEN_IDENTITIES": "/identities",
            "OPEN_ACCESSES": "/accesses",
            "CREATE_CAMPAIGN": "/campaigns/new",
            "OPEN_USERS": "/system/users",
        }.get(action_id)

    @staticmethod
    def _navigation_action(question: str) -> tuple[str, str] | None:
        text = question.casefold()
        if re.search(r"\bsi\b", text) or any(
            term in text
            for term in (
                "système d'information",
                "systeme d'information",
                "organisation",
                "périmètre",
                "perimetre",
                "scope",
            )
        ):
            return "OPEN_PERIMETERS", "Ouvrir les périmètres"
        if any(
            term in text
            for term in (
                "créer une campagne",
                "creer une campagne",
                "nouvelle campagne",
                "lancer une campagne",
            )
        ):
            return "CREATE_CAMPAIGN", "Créer une campagne"
        if any(term in text for term in ("golden", "référentiel", "referentiel")):
            return "OPEN_GOLDEN", "Ouvrir la Golden Source"
        if any(term in text for term in ("identité", "identite", "identity")):
            return "OPEN_IDENTITIES", "Ouvrir les identités"
        if any(term in text for term in ("accesses", "accès", "acces")):
            return "OPEN_ACCESSES", "Ouvrir les accès"
        if any(term in text for term in ("revue", "review")):
            return "OPEN_PENDING_REVIEWS", "Ouvrir les revues en attente"
        if any(term in text for term in ("source", "snapshot")):
            return "OPEN_SOURCES", "Ouvrir les sources"
        if any(term in text for term in ("rapport", "report")):
            return "OPEN_REPORTS", "Ouvrir les rapports"
        if any(term in text for term in ("remédiation", "remediation", "action")):
            return "OPEN_ACTIONS", "Ouvrir les remédiations"
        if any(
            term in text for term in ("utilisateurs", "users", "administration des utilisateurs")
        ):
            return "OPEN_USERS", "Ouvrir les utilisateurs"
        return None

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
            raise ProviderError("Chatbot provider is unavailable")
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
                raise ValueError("Chatbot context limit exceeded")
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
                    record_audit(
                        repo,
                        "chatbot.tool_denied",
                        context.username,
                        {
                            "conversation_id": conversation_id,
                            "tool": call.name,
                            "reason": "tool_call_limit",
                            "result_count": 0,
                        },
                    )
                    raise ValueError("Tool call limit exceeded")
                if not call.call_id or call.call_id in call_ids:
                    raise ProviderError(
                        "Chatbot returned invalid tool call id",
                        category="invalid_tool_response",
                    )
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
                    record_audit(
                        repo,
                        "chatbot.tool_denied",
                        context.username,
                        {
                            "conversation_id": conversation_id,
                            "tool": call.name,
                            "reason": "unknown_tool",
                            "result_count": 0,
                        },
                    )
                    raise ValueError("Unknown tool")
                arguments = dict(call.arguments)
                if call.name == "search_access_control_knowledge" and not self.policy.domains.get(
                    "external_guidance", False
                ):
                    self._tool_events.append(
                        {"tool": call.name, "status": "denied", "reason": "domain_disabled:external_guidance"}
                    )
                    record_audit(
                        repo,
                        "chatbot.tool_denied",
                        context.username,
                        {
                            "conversation_id": conversation_id,
                            "tool": call.name,
                            "reason": "domain_disabled:external_guidance",
                            "result_count": 0,
                        },
                    )
                    pending_outputs.append(
                        (
                            call,
                            {
                                "available": False,
                                "reason": "domain_disabled:external_guidance",
                            },
                        )
                    )
                    continue
                if (
                    call.name == "search_access_control_knowledge"
                    and self.policy.source_mode == "selected"
                ):
                    requested = arguments.get("publishers")
                    enabled = {item.casefold(): item for item in self.policy.enabled_publishers}
                    if isinstance(requested, list) and requested:
                        arguments["publishers"] = [
                            enabled[str(item).casefold()]
                            for item in requested
                            if str(item).casefold() in enabled
                        ]
                    else:
                        arguments["publishers"] = list(self.policy.enabled_publishers)
                    if not arguments["publishers"]:
                        arguments["publishers"] = ["__none_enabled__"]
                schema = next((item for item in TOOL_SCHEMAS if item["name"] == call.name), None)
                if schema is not None:
                    arguments = self._drop_optional_nulls(arguments, schema["parameters"])
                if schema is None or not validate_tool_arguments(arguments, schema):
                    self._tool_events.append(
                        {"tool": call.name, "status": "denied", "reason": "invalid_arguments"}
                    )
                    record_audit(
                        repo,
                        "chatbot.tool_denied",
                        context.username,
                        {
                            "conversation_id": conversation_id,
                            "tool": call.name,
                            "reason": "invalid_arguments",
                            "result_count": 0,
                        },
                    )
                    raise ValueError("Invalid tool arguments")
                if "limit" in arguments:
                    arguments["limit"] = min(
                        int(arguments["limit"]), self.config.max_result_items
                    )
                # Context is reconstructed by the API on every request and passed to every call.
                projected = bound_tool_output(
                    function(repo, arguments, context, hints),
                    max_items=self.config.max_result_items,
                )
                if call.name == "search_access_control_knowledge":
                    self._available_sources = {
                        str(source.get("id")): source
                        for source in projected.get("sources", [])
                        if isinstance(source, dict) and source.get("id")
                    }
                elif call.name == "select_used_knowledge_sources":
                    used_ids = {
                        str(source_id)
                        for source_id in arguments.get("source_ids", [])
                        if str(source_id) in self._available_sources
                    }
                    self._capture_sources(
                        {"sources": list(self._available_sources.values())}, used_ids
                    )
                    projected = {"source_ids": sorted(used_ids)}
                self._tool_events.append(
                    {"tool": call.name, "status": "allowed", "reason": "authorized"}
                )
                record_audit(
                    repo,
                    "chatbot.tool_allowed",
                    context.username,
                    {
                        "conversation_id": conversation_id,
                        "tool": call.name,
                        "reason": "authorized",
                        "result_count": len(projected),
                    },
                )
                pending_outputs.append((call, projected))
            messages.extend(
                item
                for item in result.output_items
                if item.get("type") in {"reasoning", "function_call"}
            )
            for call, projected in pending_outputs:
                messages.append(
                    {
                        "type": "function_call_output",
                        "call_id": call.call_id,
                        "output": json.dumps(
                            {
                                "type": "eare_data",
                                "untrusted": True,
                                "tool": call.name,
                                "data": projected,
                            },
                            ensure_ascii=False,
                            separators=(",", ":"),
                        ),
                    }
                )
        raise ValueError("Tool round limit exceeded")

    @classmethod
    def _drop_optional_nulls(
        cls, arguments: dict[str, Any], schema: dict[str, Any]
    ) -> dict[str, Any]:
        """Undo OpenAI strict-mode null placeholders before EARE validation."""
        required = set(schema.get("required", []))
        properties = schema.get("properties")
        property_schemas: dict[str, Any] = properties if isinstance(properties, dict) else {}
        result: dict[str, Any] = {}
        for key, value in arguments.items():
            if value is None and key not in required:
                continue
            child_schema = property_schemas.get(key)
            if isinstance(value, dict) and isinstance(child_schema, dict):
                value = cls._drop_optional_nulls(value, child_schema)
            result[key] = value
        return result

    def _capture_sources(
        self, projected: dict[str, Any], used_source_ids: set[str] | None = None
    ) -> None:
        existing = {source.id for source in self._sources_used}
        raw_sources = projected.get("sources")
        if not isinstance(raw_sources, list):
            return
        for raw in raw_sources:
            if not isinstance(raw, dict):
                continue
            identifier = str(raw.get("id") or "")
            if used_source_ids is not None and identifier not in used_source_ids:
                continue
            publisher = str(raw.get("publisher") or "")
            title = str(raw.get("title") or "")
            url = raw.get("url")
            parsed_url = urlparse(str(url)) if url is not None else None
            if (
                not identifier
                or identifier in existing
                or not publisher
                or not title
                or (
                    parsed_url is not None
                    and (
                        parsed_url.scheme != "https"
                        or not parsed_url.netloc
                        or parsed_url.username is not None
                        or parsed_url.password is not None
                    )
                )
            ):
                continue
            self._sources_used.append(
                AssistantSource(
                    id=identifier,
                    publisher=publisher,
                    title=title,
                    reference=str(raw.get("reference")) if raw.get("reference") else None,
                    version=str(raw.get("version")) if raw.get("version") else None,
                    url=str(url) if url else None,
                )
            )
            existing.add(identifier)
            if len(self._sources_used) >= 8:
                break


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

    def healthcheck(self) -> ProviderHealth:
        return ProviderHealth(True, "ok")
