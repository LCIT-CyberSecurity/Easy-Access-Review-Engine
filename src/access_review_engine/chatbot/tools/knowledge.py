from __future__ import annotations

from typing import Any

from access_review_engine.chatbot.context import AuthorizationContext, UIHints
from access_review_engine.chatbot.knowledge import KnowledgeCatalog
from access_review_engine.chatbot.security.tool_policy import MAX_RESULT_COUNT
from access_review_engine.storage import Repository


def search_access_control_knowledge(
    repo: Repository,
    args: dict[str, Any],
    context: AuthorizationContext,
    hints: UIHints,
) -> dict[str, Any]:
    catalog = KnowledgeCatalog.load()
    topics = tuple(str(item) for item in (args.get("topics") or []))
    publishers = tuple(str(item) for item in (args.get("publishers") or []))
    limit = min(MAX_RESULT_COUNT, max(1, int(args.get("limit") or 8)))
    entries, sources = catalog.search(
        str(args.get("query") or ""),
        topics=topics,
        publishers=publishers,
        limit=limit,
    )
    if not entries:
        return {
            "items": [],
            "sources": [],
            "count": 0,
            "limitation": (
                "No verified source in the EARE catalog precisely supports this request. "
                "Provide only general orientation and state this limitation."
            ),
        }
    return {
        "items": [
            {
                "id": entry.id,
                "topics": list(entry.topics),
                "summary": entry.summary,
                "guidance_type": entry.guidance_type,
                "applicability": entry.applicability,
                "source_ids": list(entry.source_ids),
            }
            for entry in entries
        ],
        "sources": [
            {
                "id": source.id,
                "publisher": source.publisher,
                "title": source.title,
                "reference": source.reference,
                "version": source.version,
                "publication_date": source.publication_date,
                "url": source.url,
                "jurisdiction": source.jurisdiction,
                "source_type": source.source_type,
            }
            for source in sources
        ],
        "count": len(entries),
    }


KNOWLEDGE_TOOL_FUNCTIONS = {
    "search_access_control_knowledge": search_access_control_knowledge,
}

KNOWLEDGE_TOOL_SCHEMAS = [
    {
        "type": "function",
        "name": "search_access_control_knowledge",
        "description": (
            "Search verified access-control guidance and return the only normative sources "
            "that may be cited in the answer"
        ),
        "strict": True,
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "minLength": 1, "maxLength": 400},
                "topics": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": 100},
                    "maxItems": 10,
                    "uniqueItems": True,
                },
                "publishers": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": 100},
                    "maxItems": 10,
                    "uniqueItems": True,
                },
                "limit": {"type": "integer", "minimum": 1, "maximum": 8},
            },
            "required": ["query"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function",
        "name": "select_used_knowledge_sources",
        "description": "Declare which source IDs from the preceding knowledge result were used",
        "strict": True,
        "parameters": {
            "type": "object",
            "properties": {
                "source_ids": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": 200},
                    "maxItems": 8,
                    "uniqueItems": True,
                }
            },
            "required": ["source_ids"],
            "additionalProperties": False,
        },
    }
]
