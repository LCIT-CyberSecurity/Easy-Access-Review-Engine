from __future__ import annotations

import re

from access_review_engine.chatbot.schemas import INTENTS

_SUSPICIOUS = re.compile(
    r"ignore\s+(?:all\s+|toutes?\s+)?(?:previous|prior|your|tes|vos|mes)?\s*instructions?|"
    r"ignore\s+(?:all\s+)?(?:previous|prior|your|tes|vos|mes)\s+(?:r[eè]gles?|consignes?)|"
    r"list\s+(?:all|every)\s+(?:users?|campaigns?|passwords?)|"
    r"liste\s+tous?\s+les\s+(?:utilisateurs?|campagnes?|mots?\s+de\s+passe)|"
    r"show\s+all\s+(?:secrets?|tokens?)",
    re.IGNORECASE,
)
_OUT_OF_SCOPE = re.compile(
    r"(?:recette|recipe|cr[êe]pes?|weather|m[ée]t[ée]o|joke|poem|football|translate)",
    re.IGNORECASE,
)


def classify(question: str, route: str = "/") -> str:
    if _SUSPICIOUS.search(question):
        return "SUSPICIOUS"
    if _OUT_OF_SCOPE.search(question):
        return "OUT_OF_SCOPE"
    text = question.casefold()
    if any(word in text for word in (
        "eare", "campaign", "campagne", "golden", "review", "revue", "finding",
        "remediation", "remédiation", "source", "snapshot", "report", "rapport",
    )):
        explicit = True
    else:
        explicit = False
    if any(word in text for word in ("dashboard", "situation", "attention", "maintenant")):
        return "EARE_DASHBOARD"
    if any(word in text for word in ("campaign", "campagne", "review campaign")):
        return "EARE_CAMPAIGN"
    if re.search(r"\bgolden\b|\bowner\b|\bexpected\b|functional model", text):
        return "EARE_GOLDEN"
    if any(word in text for word in ("review", "accès", "access", "unexpected", "décision")):
        return "EARE_REVIEW"
    if any(word in text for word in ("source", "snapshot", "synchron")):
        return "EARE_SOURCE"
    if any(word in text for word in ("rapport", "report", "synthèse", "summary")):
        return "EARE_REPORT"
    if any(word in text for word in ("ouvrir", "navigation", "page", "aller")):
        return "EARE_NAVIGATION"
    if any(word in text for word in ("sécurité", "security", "finding", "remediation")):
        return "EARE_SECURITY_GUIDANCE"
    normalized_route = route.split("?", 1)[0].rstrip("/") or "/"
    contextual_routes = {
        "/": "EARE_DASHBOARD",
        "/dashboard": "EARE_DASHBOARD",
        "/campaigns": "EARE_CAMPAIGN",
        "/reviews": "EARE_REVIEW",
        "/golden": "EARE_GOLDEN",
        "/sources": "EARE_SOURCE",
        "/reports": "EARE_REPORT",
    }
    for prefix, intent in contextual_routes.items():
        if normalized_route == prefix or normalized_route.startswith(prefix + "/"):
            if not explicit and re.search(
                r"\b(?:que|quoi|comment|explique|reste|compl(?:é|e)ter|faire|aide|ça|cela)\b",
                text,
            ):
                return intent
    return "OUT_OF_SCOPE"


def validate_intent(intent: str) -> str:
    return intent if intent in INTENTS else "SUSPICIOUS"
