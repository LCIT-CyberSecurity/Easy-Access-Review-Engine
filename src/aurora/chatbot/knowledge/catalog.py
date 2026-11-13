from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

GUIDANCE_TYPES = {"requirement", "recommendation", "good_practice", "technical_guidance"}
_SEARCH_STOP_WORDS = {
    "guidance",
    "guide",
    "recommendation",
    "recommendations",
    "requirement",
    "requirements",
    "practice",
    "practices",
    "security",
    "control",
    "controls",
}
_QUERY_SYNONYMS = {
    "comptes techniques": "service accounts",
    "compte technique": "service account",
    "comptes administrateurs": "administrator accounts privileged access",
    "compte administrateur": "administrator account privileged access",
    "moindre privilege": "least privilege",
    "habilitations": "access rights",
}


def _normalize(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value.casefold())
    text = "".join(char for char in decomposed if not unicodedata.combining(char))
    text = re.sub(r"[^a-z0-9]+", " ", text).strip()
    for source, target in _QUERY_SYNONYMS.items():
        text = text.replace(source, f"{source} {target}")
    return text


def _terms(value: str) -> set[str]:
    return {
        item
        for item in _normalize(value).split()
        if len(item) > 2 and item not in _SEARCH_STOP_WORDS
    }


@dataclass(frozen=True)
class KnowledgeSource:
    id: str
    publisher: str
    title: str
    reference: str | None
    version: str | None
    publication_date: str | None
    url: str
    jurisdiction: str | None
    source_type: str


@dataclass(frozen=True)
class KnowledgeEntry:
    id: str
    topics: tuple[str, ...]
    summary: str
    guidance_type: str
    applicability: str
    source_ids: tuple[str, ...]


def _official_https_url(value: object) -> str:
    url = str(value or "")
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError("Knowledge source URL must be an official HTTPS URL")
    return url


def _optional_text(value: object) -> str | None:
    return str(value).strip() if value not in {None, ""} else None


class KnowledgeCatalog:
    """Small data-driven catalog; publishers are deliberately not allowlisted in code."""

    def __init__(
        self,
        sources: tuple[KnowledgeSource, ...],
        entries: tuple[KnowledgeEntry, ...],
    ) -> None:
        self.sources = sources
        self.entries = entries
        self._sources = {source.id: source for source in sources}
        if len(self._sources) != len(sources):
            raise ValueError("Knowledge source IDs must be unique")
        if len({entry.id for entry in entries}) != len(entries):
            raise ValueError("Knowledge entry IDs must be unique")
        for entry in entries:
            if entry.guidance_type not in GUIDANCE_TYPES:
                raise ValueError("Unsupported knowledge guidance type")
            if not entry.source_ids or not set(entry.source_ids) <= set(self._sources):
                raise ValueError("Knowledge entry references an unknown source")

    @classmethod
    def load(cls, path: Path | None = None) -> KnowledgeCatalog:
        catalog_path = path or Path(__file__).with_name("catalog.json")
        raw = json.loads(catalog_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("Knowledge catalog must be an object")
        source_rows = raw.get("sources")
        entry_rows = raw.get("entries")
        if not isinstance(source_rows, list) or not isinstance(entry_rows, list):
            raise ValueError("Knowledge catalog sources and entries must be arrays")
        sources = tuple(
            KnowledgeSource(
                id=str(row["id"]),
                publisher=str(row["publisher"]),
                title=str(row["title"]),
                reference=_optional_text(row.get("reference")),
                version=_optional_text(row.get("version")),
                publication_date=_optional_text(row.get("publication_date")),
                url=_official_https_url(row.get("url")),
                jurisdiction=_optional_text(row.get("jurisdiction")),
                source_type=str(row["source_type"]),
            )
            for row in source_rows
            if isinstance(row, dict)
        )
        entries = tuple(
            KnowledgeEntry(
                id=str(row["id"]),
                topics=tuple(str(topic) for topic in row.get("topics", [])),
                summary=str(row["summary"]),
                guidance_type=str(row["guidance_type"]),
                applicability=str(row["applicability"]),
                source_ids=tuple(str(source_id) for source_id in row.get("source_ids", [])),
            )
            for row in entry_rows
            if isinstance(row, dict)
        )
        return cls(sources, entries)

    def search(
        self,
        query: str,
        *,
        topics: tuple[str, ...] = (),
        publishers: tuple[str, ...] = (),
        limit: int = 8,
    ) -> tuple[tuple[KnowledgeEntry, ...], tuple[KnowledgeSource, ...]]:
        terms = _terms(query)
        requested_topics = {term for item in topics for term in _terms(item)}
        requested_publishers = {item.casefold() for item in publishers}
        scored: list[tuple[int, KnowledgeEntry]] = []
        for entry in self.entries:
            sources = [self._sources[source_id] for source_id in entry.source_ids]
            if requested_publishers and not any(
                source.publisher.casefold() in requested_publishers for source in sources
            ):
                continue
            entry_topics = {term for topic in entry.topics for term in _terms(topic)}
            if requested_topics and not requested_topics.intersection(entry_topics):
                continue
            haystack = " ".join((entry.id, *entry.topics, entry.summary, entry.applicability))
            haystack_terms = _terms(haystack)
            score = len(terms.intersection(haystack_terms))
            publisher_score = sum(
                source.publisher.casefold() in query.casefold() for source in sources
            )
            if terms and score == 0 and publisher_score == 0 and not requested_topics:
                continue
            scored.append((score + publisher_score * 3, entry))
        selected = tuple(
            entry for _, entry in sorted(scored, key=lambda item: (-item[0], item[1].id))[:limit]
        )
        used_ids = {source_id for entry in selected for source_id in entry.source_ids}
        used_sources = tuple(source for source in self.sources if source.id in used_ids)
        return selected, used_sources
