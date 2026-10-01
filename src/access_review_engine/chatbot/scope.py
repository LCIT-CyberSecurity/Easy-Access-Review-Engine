from __future__ import annotations

import re

from access_review_engine.chatbot.schemas import INTENTS

_SUSPICIOUS = re.compile(
    r"ignore\s+(?:all\s+)?(?:previous|prior|your|tes|vos|mes)\s+instructions?|"
    r"ignore\s+(?:all\s+)?(?:previous|prior|your|tes|vos|mes)\s+(?:r[eè]gles?|consignes?)|"
    r"list\s+(?:all|every)\s+(?:users?|campaigns?|passwords?)|"
    r"show\s+all\s+(?:secrets?|tokens?)",
    re.IGNORECASE,
)
_OUT_OF_SCOPE = re.compile(
    r"(?:recette|recipe|cr[êe]pes?|weather|m[ée]t[ée]o|joke|poem|football|translate)",
    re.IGNORECASE,
)


def classify(question: str) -> str:
    if _SUSPICIOUS.search(question):
        return "SUSPICIOUS"
    if _OUT_OF_SCOPE.search(question):
        return "OUT_OF_SCOPE"
    text = question.casefold()
    if any(word in text for word in ("dashboard", "situation", "attention", "maintenant")):
        return "EARE_DASHBOARD"
    if any(word in text for word in ("campaign", "campagne", "review campaign")):
        return "EARE_CAMPAIGN"
    if any(word in text for word in ("golden", "owner", "expected", "functional model")):
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
    return "EARE_USAGE"


def validate_intent(intent: str) -> str:
    return intent if intent in INTENTS else "SUSPICIOUS"
