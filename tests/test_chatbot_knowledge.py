from __future__ import annotations

import json

import pytest
from access_review_engine.chatbot.config import ChatbotConfig
from access_review_engine.chatbot.context import AuthorizationContext, UIHints
from access_review_engine.chatbot.knowledge import KnowledgeCatalog
from access_review_engine.chatbot.providers.base import ProviderResult, ToolCall
from access_review_engine.chatbot.service import AssistantService, FakeLLMProvider
from access_review_engine.chatbot.tools.knowledge import search_access_control_knowledge
from access_review_engine.storage import Repository


def _context() -> AuthorizationContext:
    return AuthorizationContext("subject", "alice", "ADMIN", frozenset({"*"}))


@pytest.mark.parametrize(
    "publisher", ["CNIL", "ANSSI", "NIST", "ISO/IEC", "Agence du Numérique en Santé", "ENISA"]
)
def test_catalog_returns_verified_source_families(publisher, tmp_path) -> None:
    with Repository(tmp_path / "knowledge.db") as repo:
        result = search_access_control_knowledge(
            repo,
            {"query": publisher, "publishers": [publisher], "limit": 8},
            _context(),
            UIHints(),
        )
    assert result["count"] >= 1
    assert {source["publisher"] for source in result["sources"]} == {publisher}
    assert all(source["url"].startswith("https://") for source in result["sources"])


def test_unknown_guidance_returns_explicit_catalog_limitation(tmp_path) -> None:
    with Repository(tmp_path / "knowledge.db") as repo:
        result = search_access_control_knowledge(
            repo,
            {"query": "unrelated quantum cooking guidance", "limit": 4},
            _context(),
            UIHints(),
        )
    assert result["sources"] == []
    assert "No verified source" in result["limitation"]


@pytest.mark.parametrize(
    "query",
    [
        "Quelles bonnes pratiques pour les comptes techniques ?",
        "Comment appliquer le moindre privilège ?",
        "Authentification des comptes administrateurs",
    ],
)
def test_french_access_control_queries_resolve_verified_sources(tmp_path, query) -> None:
    with Repository(tmp_path / "knowledge-fr.db") as repo:
        result = search_access_control_knowledge(
            repo, {"query": query, "limit": 4}, _context(), UIHints()
        )
    assert result["count"] > 0
    assert result["sources"]


def test_catalog_rejects_dangerous_source_url(tmp_path) -> None:
    catalog = {
        "sources": [
            {
                "id": "unsafe",
                "publisher": "Example",
                "title": "Unsafe",
                "url": "javascript:alert(1)",
                "source_type": "guidance",
            }
        ],
        "entries": [
            {
                "id": "entry",
                "topics": ["access control"],
                "summary": "Summary",
                "guidance_type": "good_practice",
                "applicability": "Example",
                "source_ids": ["unsafe"],
            }
        ],
    }
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(catalog), encoding="utf-8")
    with pytest.raises(ValueError, match="HTTPS"):
        KnowledgeCatalog.load(path)


def test_catalog_accepts_new_publisher_without_code_change(tmp_path) -> None:
    catalog = {
        "sources": [
            {
                "id": "cisa-zero-trust",
                "publisher": "CISA",
                "title": "Zero Trust Maturity Model",
                "reference": "Version 2.0",
                "version": "2.0",
                "publication_date": "2023-04",
                "url": "https://www.cisa.gov/resources-tools/resources/zero-trust-maturity-model",
                "jurisdiction": "United States",
                "source_type": "public_authority_guidance",
            }
        ],
        "entries": [
            {
                "id": "cisa-access",
                "topics": ["access control"],
                "summary": "Apply contextual access controls.",
                "guidance_type": "recommendation",
                "applicability": "Zero trust programs.",
                "source_ids": ["cisa-zero-trust"],
            }
        ],
    }
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(catalog), encoding="utf-8")
    entries, sources = KnowledgeCatalog.load(path).search("access", publishers=("CISA",))
    assert [entry.id for entry in entries] == ["cisa-access"]
    assert [source.publisher for source in sources] == ["CISA"]


def test_service_exposes_only_sources_returned_by_knowledge_tool(tmp_path) -> None:
    class KnowledgeProvider(FakeLLMProvider):
        def __init__(self) -> None:
            super().__init__()
            self.round = 0

        def generate(self, messages, tools):
            self.round += 1
            self.calls.append(messages)
            if self.round == 1:
                return ProviderResult(
                    tool_calls=(
                        ToolCall(
                            "knowledge-call",
                            "search_access_control_knowledge",
                            {
                                "query": "CNIL habilitations",
                                "publishers": ["CNIL"],
                                "topics": [],
                                "limit": 4,
                            },
                        ),
                    ),
                    output_items=(
                        {
                            "type": "function_call",
                            "call_id": "knowledge-call",
                            "name": "search_access_control_knowledge",
                            "arguments": "{}",
                        },
                    ),
                )
            return ProviderResult(text="Recommandation CNIL sourcée.")

    provider = KnowledgeProvider()
    service = AssistantService(
        lambda: Repository(tmp_path / "knowledge.db"),
        ChatbotConfig(enabled=True, provider="fake", model="test"),
        provider,
    )
    principal = type(
        "Principal",
        (),
        {
            "subject": "subject",
            "username": "alice",
            "role": "ADMIN",
            "scopes": frozenset({"*"}),
        },
    )()
    result = service.handle(principal, "Que recommande la CNIL sur les habilitations ?")
    assert result["answer"] == "Recommandation CNIL sourcée."
    assert {source["publisher"] for source in result["sources"]} == {"CNIL"}
    assert len({source["id"] for source in result["sources"]}) == len(result["sources"])
    with Repository(tmp_path / "knowledge.db") as repo:
        trace = repo.list_payloads("chatbot_traces")[0]
    assert set(trace["source_ids_used"]) == {source["id"] for source in result["sources"]}
